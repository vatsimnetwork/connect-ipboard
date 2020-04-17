# IPBoard plugin for VATSIM Connect
=========================

Based on [A-Lawrence/VatsimIPBoardAuth](https://github.com/A-Lawrence/VatsimIPBoardAuth) and code from [Harrison-Scott](https://github.com/Harrison-Scott).

*// TODO: Adjust the try catch as it turns out cURL wont throw an exception*

Installing
==========

```sql
INSERT INTO `ibf_core_login_handlers` (`login_key`, `login_settings`, `login_order`, `login_acp`, `login_enabled`) VALUES ('Vatsim', '{"client_id":null,"client_secret":null,"scope":null}', '1', '0', '1');

ALTER TABLE `ibf_core_members` ADD `vatsim_cid` INT(7) UNSIGNED NULL AFTER `member_id`;

INSERT INTO `ibf_core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_client_id', 'VATSIM Connect Client ID', NULL, '100031', NULL, '0', '1', NULL, NULL);

INSERT INTO `ibf_core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_client_secret', 'VATSIM Connect Client Secret', NULL, '100031', NULL, '0', '1', NULL, NULL);

INSERT INTO `ibf_core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_scope', 'VATSIM Connect Scopes', NULL, '100031', NULL, '0', '1', NULL, NULL);

~INSERT INTO `ibf_core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_sso_requirements_url', 'You did not allow enough information.', NULL, '100031', NULL, '0', '1', NULL, NULL);
```
 


