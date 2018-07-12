<?php
$lang["enable"] = 'Turn on two factor authentication.';
$lang["optinout"] = 'Configure how users can chose to use two factor authentication: Opt-In, Opt-Out, or Mandatory.';
$lang["otpsubject"] = 'The subject line used when sending the OTP code.';
$lang["otpcontent"] = 'Message to be delivered to the recipient. Must contain "$otp" to be replaced with the OTP code.';
$lang["generatorexpiry"] = 'Number of most recent OTP codes allowed before an OTP code expires. Only valid for OTP generators like Google Authenticator.';
$lang["otplength"] = 'The number of characters to have in a OTP code.';
$lang["sentexpiry"] = 'The time, in minutes, that the OTP code is good for.';
$lang["loginnotice"] = 'Send a notice on successful login to the user. Options are never (none), user choice (user), and always send a message (always).';
$lang["loginsubject"] = 'The subject line used when notifying of successful login. "$title" is replaced with the name of the wiki.';
$lang["logincontent"] = 'Login notificaiton message sent to user. "$time" is replaced with the date and time of the login.';
$lang["refreshexpiry"] = 'The time, in minutes, that the browser can remain idle before the user is logged out.  Valid values are from 5 to 1440.  Invalid values will be clamped to this range.';
$lang["optinout_o_optin"] = 'Opt-In';
$lang["optinout_o_optout"] = 'Opt-Out';
$lang["optinout_o_mandatory"] = 'Mandatory';
$lang["loginnotice_o_none"] = 'None';
$lang["loginnotice_o_user"] = 'User';
$lang["loginnotice_o_always"] = 'Always';

$lang["logging_level"] = 'The logging level. None produces no logging. Audit records 2FA login and logout activity.  Audit+ also records sending of notifications. Debug provides detailed workflow data.  Debug+ also includes variables passed to and from functions.';
$lang["logging_path"] = 'Path and filename used to write the logs to. Defaults to the data directory. Honors absolute paths.';
$lang["logging_level_o_0"] = 'None';
$lang["logging_level_o_1"] = 'Audit';
$lang["logging_level_o_2"] = 'Audit+';
$lang["logging_level_o_3"] = 'Debug';
$lang["logging_level_o_4"] = 'Debug+';
