import assert from 'node:assert/strict';

// Native summary/button activation needs Enter's character-producing event;
// rawKeyDown alone only delivers keydown and cannot trigger that default action.
export async function pressRenderedEnter(send) {
  const key = {key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13};
  await send('Input.dispatchKeyEvent', {type: 'keyDown', ...key, text: '\r', unmodifiedText: '\r'});
  await send('Input.dispatchKeyEvent', {type: 'keyUp', ...key});
}

// macOS translates editing shortcuts in the native responder. CDP injects
// renderer events, so include the same edit command without changing the DOM.
export function platformEditEvent(event, platform = process.platform) {
  if (platform === 'darwin' && event.type !== 'keyUp' &&
      event.key === 'a' && event.modifiers === 4 && !event.commands) {
    return {...event, commands: ['selectAll']};
  }
  return event;
}

// CDP expects Windows virtual key codes, not Unicode character values. In
// particular '#' is Shift+Digit3 (51); its Unicode value 35 means End and can
// prevent macOS native select type-ahead from receiving the character.
export function renderedCharacterKey(character) {
  assert.equal([...character].length,1,'Native type-ahead requires one character');
  if(character==='#')return {code:'Digit3',native:{text:'#',unmodifiedText:'3',windowsVirtualKeyCode:51,modifiers:8}};
  const letter=/^[a-z]$/i.test(character),digit=/^[0-9]$/.test(character);
  return {code:letter?'Key'+character.toUpperCase():digit?'Digit'+character:'Unidentified',
    native:{text:character,unmodifiedText:character,
      windowsVirtualKeyCode:letter||digit?character.toUpperCase().charCodeAt(0):0}};
}

export async function selectRenderedOption({evaluate, click, key, selector, index, keyboardFocus = false}) {
  const options = await evaluate(`Array.from(document.querySelector(${JSON.stringify(selector)}).options, o => ({value:o.value,label:o.textContent.trim(),disabled:o.disabled}))`);
  const option = options[index];
  assert(option && !option.disabled, 'Requested select option must be enabled');
  // Blur any preceding type-ahead session through the keyboard before refocus.
  if (await evaluate(`document.activeElement === document.querySelector(${JSON.stringify(selector)})`)) {
    await key('Tab', 'Tab', {windowsVirtualKeyCode:9});
  }
  if (process.platform === 'darwin' || keyboardFocus) {
    // Focus with Tab instead of opening an OS popup that CDP cannot close.
    let focused = false;
    for (let attempt = 0; attempt < 200; attempt++) {
      if (await evaluate(`document.activeElement === document.querySelector(${JSON.stringify(selector)})`)) { focused = true; break; }
      await key('Tab', 'Tab', {windowsVirtualKeyCode:9});
    }
    assert(focused, 'Select must be reachable through native keyboard focus');
  }
  if (process.platform === 'darwin') {
    // Arrow keys open an OS popup on macOS. Renderer CDP input cannot operate
    // that popup. Native select type-ahead remains a real keyboard action.
    let prefix = '';
    for (const character of option.label) {
      prefix += character;
      if (options.filter(o => !o.disabled && o.label.toLowerCase().startsWith(prefix.toLowerCase())).length === 1) break;
    }
    assert(prefix && prefix.length <= 256, 'Select label must have a bounded unique prefix');
    assert.equal(options.filter(o => !o.disabled && o.label.toLowerCase().startsWith(prefix.toLowerCase())).length, 1, 'Ambiguous select label');
    for (const character of prefix) {
      const {code,native}=renderedCharacterKey(character);
      await key(character,code,native);
    }
  } else {
    if (!keyboardFocus) await click(selector);
    await key('Home', 'Home', {windowsVirtualKeyCode:36});
    for (let i = 0; i < index; i++) await key('ArrowDown', 'ArrowDown', {windowsVirtualKeyCode:40});
    await key('Enter', 'Enter', {windowsVirtualKeyCode:13, text:'\r', unmodifiedText:'\r'});
  }
  assert.equal(await evaluate(`document.querySelector(${JSON.stringify(selector)}).value`), option.value, 'Rendered keyboard selection must retain the exact option value');
}
