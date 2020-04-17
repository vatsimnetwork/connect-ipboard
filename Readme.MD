# IPBoard plugin for VATSIM Connect
=========================

Based on [A-Lawrence/VatsimIPBoardAuth](https://github.com/A-Lawrence/VatsimIPBoardAuth) and code from [Harrison-Scott](https://github.com/Harrison-Scott).

*// TODO: Adjust the try catch as it turns out cURL wont throw an exception*

Installing
==========

- Take a backup. Please!
- Copy all files into system/Login
Run the following MySQL Commands to add this login handler to your installation, add a vatsim_cid field to the members table and then adds some needed entries to your languages table (English only). make sure that you edit the queries to match your IPBoard prefix if it isn't default.

```sql
INSERT INTO `core_login_methods` (`login_classname`, `login_settings`, `login_order`, `login_acp`, `login_enabled`, `login_register`) VALUES ('IPS\Login\VATSIMSSOv2', '{"client_id":null,"client_secret":null,"scope":null,"sso_requirements_url":null, "base_url":null}', '4', '1', '0', '0');

ALTER TABLE `core_members` ADD `vatsim_cid` INT(7) UNSIGNED NULL AFTER `member_id`;
```
 


