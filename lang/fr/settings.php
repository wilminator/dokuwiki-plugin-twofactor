<?php
$lang["enable"] = "Activer l'authentification multi-factorielle.";
$lang["optinout"] = "Configurez la façon dont les utilisateurs peuvent utiliser l'authentification multi-facteurs : Opt-in, Opt-out ou obligatoire.";
$lang["otpsubject"] = 'The subject line used when sending the OTP code.';
$lang["otpcontent"] = 'Message envoyé au destinataire. Doit contenir "$otp" qui est remplacé par le code OTP.';
$lang["generatorexpiry"] = "Nombre de codes OTP récents autorisés avant qu'un code OTP n'expire. Seulement valide avec les générateurs de codes OTP comme Google Authenticator.";
$lang["otplength"] = 'Nombre de caractères du code OTP.';
$lang["sentexpiry"] = 'Le temps, en minutes, de validité du code OTP.';
$lang["loginnotice"] = "Envoyer une notification à l'utilisateurs lors d'une identification avec succès. Les options sont jamais (none), au choix de l'utilisateur (user) ou toujours envoyer un message (always).";
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
