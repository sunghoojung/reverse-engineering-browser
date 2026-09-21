#!/usr/bin/env node

const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const t = require("@babel/types");
const generate = require("@babel/generator").default;

const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const MAX_ITERATIONS = 8;
const UNKNOWN = Symbol("unknown");
const UNDEFINED = Symbol("undefined");
const HOLE = Symbol("array-hole");

function isKnown(value) {
  return value !== UNKNOWN;
}

function isTruthy(value) {
  if (value === UNDEFINED || value === null || value === false || value === 0 || value === "") return false;
  return true;
}

function safeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : UNKNOWN;
}

function literal(value) {
  if (value === UNDEFINED) return t.unaryExpression("void", t.numericLiteral(0), true);
  if (value === UNKNOWN || value === HOLE || typeof value === "function" || typeof value === "object") return null;
  return t.valueToNode(value);
}

function staticValue(node, environment = new Map()) {
  if (!node) return UNKNOWN;
  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return node.value;
  if (t.isNullLiteral(node)) return null;
  if (t.isIdentifier(node) && environment.has(node.name)) return environment.get(node.name);
  if (t.isUnaryExpression(node)) {
    if (node.operator === "void") return UNDEFINED;
    if (node.operator === "delete") return UNKNOWN;
    const value = staticValue(node.argument, environment);
    if (!isKnown(value) || value === HOLE) return UNKNOWN;
    if (node.operator === "!") return !isTruthy(value);
    if (node.operator === "+") return safeNumber(Number(value));
    if (node.operator === "-") return safeNumber(-Number(value));
    if (node.operator === "~") return ~Number(value);
    if (node.operator === "typeof") return value === UNDEFINED ? "undefined" : typeof value;
    return UNKNOWN;
  }
  if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
    const left = staticValue(node.left, environment);
    if (!isKnown(left) || left === HOLE) return UNKNOWN;
    if (node.operator === "&&" && !isTruthy(left)) return left;
    if (node.operator === "||" && isTruthy(left)) return left;
    const right = staticValue(node.right, environment);
    if (!isKnown(right) || right === HOLE) return UNKNOWN;
    let result;
    switch (node.operator) {
      case "+": result = left + right; break;
      case "-": result = left - right; break;
      case "*": result = left * right; break;
      case "/": result = right === 0 ? UNKNOWN : left / right; break;
      case "%": result = right === 0 ? UNKNOWN : left % right; break;
      case "**": result = left ** right; break;
      case "^": result = left ^ right; break;
      case "&": result = left & right; break;
      case "|": result = left | right; break;
      case "<<": result = left << right; break;
      case ">>": result = left >> right; break;
      case ">>>": result = left >>> right; break;
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
    return typeof result === "number" && !Number.isFinite(result) ? UNKNOWN : result;
  }
  if (t.isConditionalExpression(node)) {
    const test = staticValue(node.test, environment);
    if (!isKnown(test) || test === HOLE) return UNKNOWN;
    return staticValue(isTruthy(test) ? node.consequent : node.alternate, environment);
  }
  if (t.isArrayExpression(node)) {
    const values = [];
    for (const element of node.elements) {
      if (element === null) {
        values.push(HOLE);
        continue;
      }
      const value = staticValue(element, environment);
      if (!isKnown(value)) return UNKNOWN;
      values.push(value);
    }
    return values;
  }
  if (t.isMemberExpression(node) && node.computed) {
    const object = staticValue(node.object, environment);
    const property = staticValue(node.property, environment);
    if (!isKnown(object) || !isKnown(property) || object == null) return UNKNOWN;
    if ((Array.isArray(object) || typeof object === "string") && Number.isInteger(property) && property >= 0) {
      if (property >= object.length) return UNDEFINED;
      return object[property] === HOLE ? UNDEFINED : object[property];
    }
    return UNKNOWN;
  }
  return UNKNOWN;
}

function recordTransform(transforms, kind, node) {
  if (!transforms || !node || !Number.isInteger(node.start) || !Number.isInteger(node.end)) return;
  transforms.push({kind, originalStart: node.start, originalEnd: node.end});
}

function replaceWithLiteral(path, value, kind, transforms) {
  const node = literal(value);
  if (!node) return false;
  recordTransform(transforms, kind, path.node);
  path.replaceWith(node);
  return true;
}

function foldConstants(ast, transforms) {
  let count = 0;
  traverse(ast, {
    "BinaryExpression|LogicalExpression|UnaryExpression|ConditionalExpression": {
      exit(path) {
        if (t.isUnaryExpression(path.node) && ["void", "delete"].includes(path.node.operator)) return;
        // Babel represents negative numeric literals as UnaryExpression nodes.
        // Replacing `-7` with valueToNode(-7) would recreate the same node and
        // recurse forever, so only fold a negative unary expression once its
        // operand is no longer already a numeric literal.
        if (t.isUnaryExpression(path.node) && path.node.operator === "-" && t.isNumericLiteral(path.node.argument)) return;
        const value = staticValue(path.node);
        if (value !== UNKNOWN && replaceWithLiteral(path, value, "constant-fold", transforms)) count += 1;
      },
    },
  });
  return count;
}

function substituteConstants(ast, transforms) {
  let count = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      const binding = path.scope.getBinding(path.node.id.name);
      const value = staticValue(path.node.init);
      if (!binding || !binding.constant || value === UNKNOWN || Array.isArray(value) && value.some((item) => item === HOLE || item === UNDEFINED)) return;
      let replacedAll = true;
      for (const reference of [...binding.referencePaths]) {
        if (reference.removed) continue;
        if (replaceWithLiteral(reference, value, "constant-substitution", transforms)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) {
        recordTransform(transforms, "remove-constant-binding", path.node);
        path.remove();
      }
    },
  });
  return count;
}

function replaceStringArrayAccesses(ast, transforms) {
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
        recordTransform(transforms, "string-array-recovery", parent.node);
        parent.replaceWith(t.stringLiteral(values[index]));
        count += 1;
      }
      if (replacedAll) {
        recordTransform(transforms, "remove-string-table", path.node);
        path.remove();
      }
    },
  });
  return count;
}

function inlinePureProxies(ast, transforms) {
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
        if (value !== UNKNOWN && replaceWithLiteral(call, value, "inline-pure-proxy", transforms)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) {
        recordTransform(transforms, "remove-pure-proxy", path.node);
        path.remove();
      }
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
        if (value !== UNKNOWN && replaceWithLiteral(call, value, "inline-pure-proxy", transforms)) count += 1;
        else replacedAll = false;
      }
      if (replacedAll) {
        recordTransform(transforms, "remove-pure-proxy", path.node);
        path.remove();
      }
    },
  });
  return count;
}

function removeDeadBranches(ast, transforms) {
  let count = 0;
  traverse(ast, {
    IfStatement(path) {
      const value = staticValue(path.node.test);
      if (!isKnown(value) || value === HOLE) return;
      const chosen = isTruthy(value) ? path.node.consequent : path.node.alternate;
      recordTransform(transforms, "remove-dead-branch", path.node);
      if (!chosen) path.remove();
      else if (t.isBlockStatement(chosen)) path.replaceWithMultiple(chosen.body);
      else path.replaceWith(chosen);
      count += 1;
    },
    ConditionalExpression(path) {
      const value = staticValue(path.node.test);
      if (!isKnown(value) || value === HOLE) return;
      recordTransform(transforms, "fold-conditional", path.node);
      path.replaceWith(isTruthy(value) ? path.node.consequent : path.node.alternate);
      count += 1;
    },
  });
  return count;
}

function normalizeMemberAccess(ast, transforms) {
  let count = 0;
  traverse(ast, {
    MemberExpression(path) {
      if (!path.node.computed || !t.isStringLiteral(path.node.property)) return;
      if (!/^[$A-Z_a-z][$\w]*$/.test(path.node.property.value)) return;
      recordTransform(transforms, "normalize-member-access", path.node);
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
  const transforms = [];
  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration += 1) {
    const counts = {
      foldConstants: foldConstants(ast, transforms),
      substituteConstants: substituteConstants(ast, transforms),
      replaceStringArrayAccesses: replaceStringArrayAccesses(ast, transforms),
      inlinePureProxies: inlinePureProxies(ast, transforms),
      removeDeadBranches: removeDeadBranches(ast, transforms),
      normalizeMemberAccess: normalizeMemberAccess(ast, transforms),
    };
    const changed = Object.values(counts).reduce((total, value) => total + value, 0);
    passes.push({iteration, counts, changed});
    if (!changed) break;
  }
  return {schema: "ast-deobfuscation-poc-v1", passes, transforms, code: generate(ast, {comments: true}).code};
}

if (require.main === module) {
  const source = fs.readFileSync(process.argv[2], "utf8");
  process.stdout.write(JSON.stringify(deobfuscate(source), null, 2) + "\n");
}

module.exports = {deobfuscate, staticValue, UNKNOWN};
