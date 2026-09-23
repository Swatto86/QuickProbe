const test = require('node:test');
const assert = require('node:assert/strict');
const { shouldPromptForUpdate } = require('../../ui/update-logic.js');

test('does not prompt when the running version is already the latest', () => {
    const info = { available: false, current_version: '2.1.7', version: '2.1.7' };
    assert.equal(shouldPromptForUpdate(info), false);
});

test('prompts when the backend reports a newer release', () => {
    const info = { available: true, current_version: '2.1.7', version: '2.1.8' };
    assert.equal(shouldPromptForUpdate(info), true);
});

test('does not prompt without update information', () => {
    assert.equal(shouldPromptForUpdate(null), false);
    assert.equal(shouldPromptForUpdate(undefined), false);
    assert.equal(shouldPromptForUpdate({}), false);
});
