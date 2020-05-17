# IPBoard plugin for VATSIM Connect
=========================

Based on [A-Lawrence/VatsimIPBoardAuth](https://github.com/A-Lawrence/VatsimIPBoardAuth) and code from [Harrison-Scott](https://github.com/Harrison-Scott).

Working `IPB Version 

*// TODO: Adjust the try catch as it turns out cURL wont throw an exception*

Installing
==========

- Take a backup. Please!
- Copy all files into system/Login
Run the following MySQL Commands to add this login handler to your installation, add a vatsim_cid field to the members table and then adds some needed entries to your languages table (English only). make sure that you edit the queries to match your IPBoard prefix if it isn't default.

```sql
INSERT INTO `core_login_methods` (`login_classname`, `login_settings`, `login_order`, `login_acp`, `login_enabled`, `login_register`) VALUES ('IPS\Login\VATSIMSSOv2', '{"client_id":null,"client_secret":null,"scope":null,"sso_requirements_url":null, "base_url":null}', '4', '1', '0', '0');

ALTER TABLE `core_members` ADD `vatsim_cid` INT(7) UNSIGNED NULL AFTER `member_id`;

INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_handler_Vatsim', 'VATSIM SSO Login', NULL, '100031', NULL, '0', '1', NULL, NULL);
INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_base_url', 'Forum Base URL', NULL, '100031', NULL, '0', '1', NULL, NULL);
INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_client_id', 'VATSIM Auth Client ID', NULL, '100031', NULL, '0', '1', NULL, NULL);
INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_client_secret', 'VATSIM Auth Client Secret', NULL, '100031', NULL, '0', '1', NULL, NULL);
INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_sso_requirements_url', 'VATSIM Auth Requirements URL', NULL, '100031', NULL, '0', '1', NULL, NULL);
INSERT INTO `core_sys_lang_words` (`word_id`, `lang_id`, `word_app`, `word_key`, `word_default`, `word_custom`, `word_default_version`, `word_custom_version`, `word_js`, `word_export`, `word_plugin`, `word_theme`) VALUES (NULL, '1', 'core', 'login_vatsim_scope', 'VATSIM Auth Scope', NULL, '100031', NULL, '0', '1', NULL, NULL);
```
 
- Login to your Admin Control Panel, visit System > Settings > Login Handlers
- Edit the Vatsim Login Handler and complete the form with the details requested. You can get these from the VATSIM SSO website once you've registered as an SSO consumer.
- Visit Customisation > Themes and click "Edit HTML/CSS" for the default theme (you'll have to figure out these steps for any custom/purchased templates)
- Locate loginPopup in the global section and modify it to match: https://gist.github.com/A-Lawrence/d0fe1ffcf13c15e1926d (What we're achiving here is disabling the normal login for users)
- Locate login in the system section and modify it to match: https://gist.github.com/A-Lawrence/135238e6aff855fcb571 (We're also disabling normal login from the standard login screen)
- Add the following code to the following template (theme of your choice) `core/front/global/customFieldsDisplay/` under the existing foreach code.
```html
<li class='ipsResponsive_hidePhone ipsType_break'>VATSIM ID: {$author->vatsim_cid}</li>
```
Save those templates (your forum may lose it's styling momentarily whils the style caches are rebuilt)
That's it! Go and use it.

