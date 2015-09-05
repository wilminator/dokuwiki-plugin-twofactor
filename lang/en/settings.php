<?php
$lang["enable"] = 'Turn on two factor authentication';
$lang["optinout"] = 'Configure how users can chose to use two factor authentication: OptIn, OptOut, or Mandatory.';
$lang["usega"] = 'Enable Google Authenticator (GA) Two-Factor';
$lang["gasecret"] = 'Shared secret for GA. If not provided, each user will be issued a unique secret.';
$lang["gaexpiry"] = 'Number of most recent OTP codes allowed before an OTP code expires.';
$lang["useotp"] = 'Enable use of a one time password';
$lang["otpmethod"] = 'Provide the method of delivering the one time password. Can be by email, SMS gateway (via email), or SMS appliance.';
$lang["otpurl"] = 'URL used to connect to the SMS appliance. "$phone" will be replaced with the phone number. "$msg" will be replaced with the message.';
$lang["otpcontent"] = 'Message to be delivered to the recipient. Must contain "$otp" to be replaced with the OTP code.';
$lang["otplength"] = 'The number of characters to have in a OTP code.';
$lang["otpexpiry"] = 'The time, in minutes, that the OTP code is good for.';
