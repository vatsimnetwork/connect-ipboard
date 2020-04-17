# IPBoard plugin for VATSIM Connect
=========================

Based on [A-Lawrence/VatsimIPBoardAuth](https://github.com/A-Lawrence/VatsimIPBoardAuth) and code from [Harrison-Scott](https://github.com/Harrison-Scott).

*// TODO: Adjust the try catch as it turns out cURL wont throw an exception*

Installing
==========

```sql
INSERT INTO `ibf_core_login_handlers` (`login_key`, `login_settings`, `login_order`, `login_acp`, `login_enabled`) VALUES ('Vatsim', '{"client_id":null,"client_secret":null,"scope":null}', '1', '0', '1');

ALTER TABLE `ibf_core_members` ADD `vatsim_cid` INT(7) UNSIGNED NULL AFTER `member_id`;
```
 


