/**
 * Update decisions shared by update-required.js and its Node unit tests.
 *
 * The update-required window is created (hidden) at every start-up and loads this page,
 * so it must present an update only when the backend reports that one is available.
 */

/**
 * @param {{available?: boolean} | null | undefined} info - result of `check_for_update`
 * @returns {boolean} true only when a newer release is available
 */
function shouldPromptForUpdate(info) {
    return Boolean(info && info.available === true);
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { shouldPromptForUpdate };
}
