#!/usr/bin/env node

const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const t = require("@babel/types");
const generate = require("@babel/generator").default;

const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const MAX_ITERATIONS = 8;
const UNKNOWN = Symbol("unknown");

function literal(value) {
  if (value === undefined || typeof value === "function" || typeof value === "object") return null;
  return t.valueToNode(value);
}

function staticValue(node, environment = new Map()) {
  if (!node) return UNKNOWN;
  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return node.value;
  if (t.isNullLiteral(node)) return null;
  if (t.isIdentifier(node) && environment.has(node.name)) return environment.get(node.name);
  if (t.isUnaryExpression(node) && node.operator !== "void") {
    const value = staticValue(node.argument, environment);
    if (value === UNKNOWN) return UNKNOWN;
    if (node.operator === "!") return !value;
    if (node.operator === "+") return +value;
    if (node.operator === "-") return -value;
    if (node.operator === "~") return ~value;
    if (node.operator === "typeof") return typeof value;
    return UNKNOWN;
  }
  if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
    const left = staticValue(node.left, environment);
    if (left === UNKNOWN) return UNKNOWN;
    if (node.operator === "&&" && !left) return left;
    if (node.operator === "||" && left) return left;
    const right = staticValue(node.right, environment);
    if (right === UNKNOWN) return UNKNOWN;
    switch (node.operator) {
      case "+": return left + right;
      case "-": return left - right;
      case "*": return left * right;
      case "/": return right === 0 ? UNKNOWN : left / right;
      case "%": return right === 0 ? UNKNOWN : left % right;
      case "**": return left ** right;
      case "^": return left ^ right;
      case "&": return left & right;
      case "|": return left | right;
      case "<<": return left << right;
      case ">>": return left >> right;
      case ">>>": return left >>> right;
      case "===": return left === right;
      case "!==": return left !== right;
      case "==": return left == right;
      case "!=": return left != right;
      case "<": return left < right;
      case "<=": return left <= right;
      case ">": return left > right;
      case ">=": return left >= right;
      case "&&": return right;
      case "||": return right;
      default: return UNKNOWN;
    }
  }
  if (t.isConditionalExpression(node)) {
    const test = staticValue(node.test, environment);
    if (test === UNKNOWN) return UNKNOWN;
    return staticValue(test ? node.consequent : node.alternate, environment);
  }
  if (t.isArrayExpression(node)) {
    const values = [];
    for (const element of node.elements) {
      const value = staticValue(element, environment);
      if (value === UNKNOWN) return UNKNOWN;
      values.push(value);
    }
    return values;
  }
  if (t.isMemberExpression(node) && node.computed) {
    const object = staticValue(node.object, environment);
    const property = staticValue(node.property, environment);
    if (object === UNKNOWN || property === UNKNOWN || object == null) return UNKNOWN;
    if ((Array.isArray(object) || typeof object === "string") && Number.isInteger(property) && property >= 0) return object[property];
    return UNKNOWN;
  }
  return UNKNOWN;
}

function replaceWithLiteral(path, value) {
  const node = literal(value);
  if (!node) return false;
  path.replaceWith(node);
  return true;
}

function foldConstants(ast) {
  let count = 0;
  traverse(ast, {
    "BinaryExpression|LogicalExpression|UnaryExpression|ConditionalExpression": {
      exit(path) {
        if (t.isUnaryExpression(path.node) && ["void", "delete"].includes(path.node.operator)) return;
        const value = staticValue(path.node);
        if (value !== UNKNOWN && replaceWithLiteral(path, value)) count += 1;
      },
    },
  });
  return count;
}

function substituteConstants(ast) {
  let count = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const binding = path.scope.getBinding(path.node.id.name);
      const value = staticValue(path.node.init);
      if (!binding || !binding.constant || value === UNKNOWN || Array.isArray(value) && value.some((item) => item === undefined)) return;
      let replacedAll = true;
      for (const reference of [...binding.referencePaths]) {
        if (reference.removed) continue;
        if (replaceWithLiteral(reference, value)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) path.remove();
    },
  });
  return count;
}

function replaceStringArrayAccesses(ast) {
  let count = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || !t.isArrayExpression(path.node.init)) return;
      const values = path.node.init.elements.map((element) => staticValue(element));
      if (values.some((value) => value === UNKNOWN || typeof value !== "string")) return;
      const binding = path.scope.getBinding(path.node.id.name);
      if (!binding || !binding.constant) return;
      let replacedAll = true;
      for (const reference of [...binding.referencePaths]) {
        const parent = reference.parentPath;
        if (!parent.isMemberExpression() || parent.node.object !== reference.node || !parent.node.computed) {
          replacedAll = false;
          continue;
        }
        const index = staticValue(parent.node.property);
        if (!Number.isInteger(index) || index < 0 || index >= values.length) {
          replacedAll = false;
          continue;
        }
        parent.replaceWith(t.stringLiteral(values[index]));
        count += 1;
      }
      if (replacedAll) path.remove();
    },
  });
  return count;
}

function inlinePureProxies(ast) {
  let count = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || !t.isArrowFunctionExpression(path.node.init)) return;
      const functionNode = path.node.init;
      const returnExpression = t.isBlockStatement(functionNode.body)
        ? functionNode.body.body.length === 1 && t.isReturnStatement(functionNode.body.body[0]) ? functionNode.body.body[0].argument : null
        : functionNode.body;
      if (!returnExpression) return;
      const binding = path.scope.getBinding(path.node.id.name);
      if (!binding || !binding.constant) return;
      let replacedAll = true;
      for (const reference of [...binding.referencePaths]) {
        const call = reference.parentPath;
        if (!call.isCallExpression() || call.node.callee !== reference.node) {
          replacedAll = false;
          continue;
        }
        if (call.node.arguments.length !== functionNode.params.length) {
          replacedAll = false;
          continue;
        }
        const environment = new Map();
        let valid = true;
        functionNode.params.forEach((param, index) => {
          if (!t.isIdentifier(param)) valid = false;
          else environment.set(param.name, staticValue(call.node.arguments[index]));
        });
        const value = valid ? staticValue(returnExpression, environment) : UNKNOWN;
        if (value !== UNKNOWN && replaceWithLiteral(call, value)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) path.remove();
    },
    FunctionDeclaration(path) {
      const body = path.node.body.body;
      if (body.length !== 1 || !t.isReturnStatement(body[0]) || !path.node.id) return;
      const binding = path.scope.getBinding(path.node.id.name);
      if (!binding || !binding.constant) return;
      let replacedAll = true;
      for (const reference of [...binding.referencePaths]) {
        const call = reference.parentPath;
        if (!call.isCallExpression() || call.node.callee !== reference.node || call.node.arguments.length !== path.node.params.length) {
          replacedAll = false;
          continue;
        }
        const environment = new Map();
        let valid = true;
        path.node.params.forEach((param, index) => {
          if (!t.isIdentifier(param)) valid = false;
          else environment.set(param.name, staticValue(call.node.arguments[index]));
        });
        const value = valid ? staticValue(body[0].argument, environment) : UNKNOWN;
        if (value !== UNKNOWN && replaceWithLiteral(call, value)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) path.remove();
    },
  });
  return count;
}

function removeDeadBranches(ast) {
  let count = 0;
  traverse(ast, {
    IfStatement(path) {
      const value = staticValue(path.node.test);
      if (value === UNKNOWN) return;
      const chosen = value ? path.node.consequent : path.node.alternate;
      if (!chosen) path.remove();
      else if (t.isBlockStatement(chosen)) path.replaceWithMultiple(chosen.body);
      else path.replaceWith(chosen);
      count += 1;
    },
    ConditionalExpression(path) {
      const value = staticValue(path.node.test);
      if (value === UNKNOWN) return;
      path.replaceWith(value ? path.node.consequent : path.node.alternate);
      count += 1;
    },
  });
  return count;
}

function normalizeMemberAccess(ast) {
  let count = 0;
  traverse(ast, {
    MemberExpression(path) {
      if (!path.node.computed || !t.isStringLiteral(path.node.property)) return;
      if (!/^[$A-Z_a-z][$\w]*$/.test(path.node.property.value)) return;
      path.replaceWith(t.memberExpression(path.node.object, t.identifier(path.node.property.value), false));
      count += 1;
    },
  });
  return count;
}

function deobfuscate(source) {
  if (Buffer.byteLength(source, "utf8") > MAX_SOURCE_BYTES) throw new Error("source exceeds limit");
  const ast = parser.parse(source, {sourceType: "unambiguous", errorRecovery: false});
  const passes = [];
  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration += 1) {
    const counts = {
      foldConstants: foldConstants(ast),
      substituteConstants: substituteConstants(ast),
      replaceStringArrayAccesses: replaceStringArrayAccesses(ast),
      inlinePureProxies: inlinePureProxies(ast),
      removeDeadBranches: removeDeadBranches(ast),
      normalizeMemberAccess: normalizeMemberAccess(ast),
    };
    const changed = Object.values(counts).reduce((total, value) => total + value, 0);
    passes.push({iteration, counts, changed});
    if (!changed) break;
  }
  return {schema: "ast-deobfuscation-poc-v1", passes, code: generate(ast, {comments: true}).code};
}

if (require.main === module) {
  const source = fs.readFileSync(process.argv[2], "utf8");
  process.stdout.write(JSON.stringify(deobfuscate(source), null, 2) + "\n");
}

module.exports = {deobfuscate, staticValue, UNKNOWN};
