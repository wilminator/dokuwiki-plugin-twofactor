<?php
# User menu text
$lang['btn_twofactor_profile'] = 'Two Factor Settings';

# Two Factor profile header and settings
$lang['settings'] = "Two Factor Settings";
$lang['twofactor_optin'] = "Use two factor authentication";
$lang['twofactor_notify'] = "Send notification upon sucessful login to default device";
$lang['defaultmodule'] = "Default way to receive a code";
$lang['useallotp'] = "*Use All*";
$lang['verify_password'] = "Confirm your password";
$lang['btn_quit'] = "Quit";
$lang['btn_return'] = "Return to content";

# Messages displayed by menu
$lang['updated'] = "Two factor configuration updated.";
$lang['mandatory'] = "This wiki requires the use of two factor authentication.  You must configure at least one form of two factor authentication to continue.";

# Text used at login
$lang['twofactor_login'] = "Two Factor Authentication Token<br />(leave blank if not using)<br />";
$lang['mustusetoken'] = "This wiki requires the use of a token provider such as Google Authenticator to login.";

# Text used at OTP login screen
$lang['twofactor_otplogin'] = "Verification Code";
$lang['twofactor_useallmods'] = "Resend OTP using all configured options";
$lang['twofactor_invalidotp'] = "The code supplied is incorrect or expired.  Please try again. If needed, click the link to resend your code.";
$lang['btn_login'] = "Complete Login";
$lang['btn_resend'] = "Resend Code";

# Administrative text
$lang['menu'] = 'TwoFactor Admin';
$lang['noauth']      = 'Unable to administer TwoFactor: User authentication module not available.';
$lang['nosupport']   = 'Unable to administer TwoFactor: User management not supported via authentication module.';
$lang['badauth']     = 'invalid auth mechanism';     // should never be displayed!
$lang['user_id']     = 'User';
$lang['user_pass']   = 'Password';
$lang['user_name']   = 'Real Name';
$lang['user_mail']   = 'Email';
$lang['reset_selected'] = 'Reset Selected';
$lang['search']      = 'Search';
$lang['search_prompt'] = 'Perform search';
$lang['clear']       = 'Reset Search Filter';
$lang['filter']      = 'Filter';
$lang['start']  = 'start';
$lang['prev']   = 'previous';
$lang['next']   = 'next';
$lang['last']   = 'last';
$lang['summary']     = 'Displaying users %1$d-%2$d of %3$d found. %4$d users total.';
$lang['nonefound']   = 'No users found. %d users total.';
$lang['reset_ok']   = '%d users reset';
$lang['reset_not_self']   = "You can't reset yourself.";
$lang['no_purpose']   = "The TwoFactor plugin depends on the Attribute helper plugin being installed. Without the Attrubute plugin, TwoFactor cannot store data and will not function.";
