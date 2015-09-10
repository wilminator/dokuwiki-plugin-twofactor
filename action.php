<?php
// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();
/**
 * Two Factor Action Plugin
 *
 * @author Mike Wilmes mwilmes@avc.edu
 * Big thanks to Daniel Popp and his Google 2FA code (authgoogle2fa) as a starting reference.
 */

// Load the PHPGangsta_GoogleAuthenticator Class
require_once(dirname(__FILE__).'/GoogleAuthenticator.php');
// Load the PHP QR Code library.
require_once(dirname(__FILE__).'/phpqrcode.php');

class action_plugin_twofactor extends DokuWiki_Action_Plugin {
	public $success = false;
	private $attribute = null;

	public function __construct() {
		$this->loadConfig();
		// Load the attribute helper if GA is active or not requiring use of email to send the OTP.
		$requireAttribute = $this->getConf("enable") === 1;
		$this->attribute = $requireAttribute ? $this->loadHelper('attribute', 'Attribute plugin required!') : null;		
		$this->success = !$requireAttribute || ($this->attribute && $this->attribute->success);

		// This is a check flag to verify that the user's profile is being updated.
		$this->modifyProfile = false;
	}

	/**
	 * return some info
	 */
	function getInfo(){
		return array(
            'author' => 'Mike Wilmes',
            'email'  => 'mwilmes@avc.edu',
            'date'   => '2015-09-04',
            'name'   => 'TwoFactor Plugin',
            'desc'   => 'This plugin provides for two factor authentication using either Google Authenticator or one time passwords sent by email or SMS appliance.',
            'url'    => 'http://www.dokuwiki.org/plugin:twofactor',
		);
	}

    /**
     * Registers the event handlers.
     */
    function register(&$controller)
    {
        if($this->getConf("enable") === 1 && $this->success) {
			if ($this->getConf("usega") === 1) {
				$controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'twofactor_login_form', array());				
			}
			$controller->register_hook('AUTH_LOGIN_CHECK', 'BEFORE', $this, 'twofactor_before_auth_check', array());
			$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'twofactor_after_auth_check', array());
            $controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'twofactor_prompt_otp', array());
            $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'twofactor_profile_form', array());
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'twofactor_action_process_handler', array());
            $controller->register_hook('AUTH_USER_CHANGE', 'AFTER', $this, 'twofactor_process_changes', array());
        }
    }
    /**
     * Handles the login form rendering.
     */
    function twofactor_login_form(&$event, $param) {
		$twofa_form = form_makeTextField('otp', '', $this->getLang('twofactor_login'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
        $pos = $event->data->findElementByAttribute('type', 'submit');
        $event->data->insertElement($pos-1, $twofa_form);
    }
    /**
     * Handles the profile form rendering.  Displays user manageable settings.
     */
    function twofactor_profile_form(&$event, $param) {
		$optinout = $this->getConf("optinout");
		$optstate = $optinout == 'mandatory' ? 'in' : ($this->attribute ? $this->attribute->get("twofactor","state") : '');
		$gaavailable = $this->getConf("usega") === 1 && $this->attribute->exists("twofactor","seenqrcode");
		$otpmethod = $this->getConf("otpmethod");
		$otpenabled = $this->getConf("useotp") === 1;
		$otpavailable = $otpenabled && ($otpmethod === 'email' || $this->attribute->exists("twofactor","seensms"));
		
		// If the user is being redirected here because of mandatory two factor, then display a message saying so.
		if (!$gaavailable && !$otpavailable && $optinout == 'mandatory') {
			msg($this->getLang('twofactor_mandatory'), -1);
		}

		global $USERINFO;
		// Get the location just above the submit buttons.
		$pos = $event->data->findElementByAttribute('type', 'submit') - 1;
		// Add the checkbox to opt in and out, only if optinout is not mandatory.
		if ($this->getConf("optinout") != 'mandatory') {
			$value = $optstate;
			if (!$this->attribute || !$value) {  // If there is no personal setting for optin, the default is based on the wiki default.
				$value = $this->getConf("optinout") == 'optout';
			}
			$twofa_form = form_makeCheckboxField('optinout', '1', $this->getLang('twofactor_optin'), '', 'block', $value=='in'?array('checked'=>'checked'):array());
			$event->data->insertElement($pos++, $twofa_form);
		}
		// Add the image and prompt to use GA if available, or the check to undo personal GA if in use.
		if ($optstate == 'in' && $this->getConf("usega") == 1) {			
			$ga = new PHPGangsta_GoogleAuthenticator();			
			if ($this->attribute->exists("twofactor","secret")) { // The user has a revokable GA secret.
				// Show the QR code so the user can add other devices.
				$mysecret = $this->attribute->get("twofactor","secret");
				$event->data->insertElement($pos++, '<figure><figcaption>'.$this->getLang('twofactor_scanwithga').'</figcaption>');
				$data = $this->twofactor_generateQRCodeData($USERINFO['mail'], $mysecret);			
				$event->data->insertElement($pos++, '<img src="'.$data.'" alt="'.$this->getLang('twofactor_scanwithga').'" />');
				$event->data->insertElement($pos++, '</figure>');
				// Check to see if the user needs to verify the code.
				if (!$this->attribute->exists("twofactor","seenqrcode")){
					$event->data->insertElement($pos++, '<span>'.$this->getLang('twofactor_verifyga').'</span>');
					$twofa_form = form_makeTextField('verifyga', '', $this->getLang('twofactor_codefromga'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
					$event->data->insertElement($pos++, $twofa_form);
				}
				// Show the option to revoke the GA secret.
				$twofa_form = form_makeCheckboxField('killgasecret', '1', $this->getLang('twofactor_killgasecret'), '', 'block');
				$event->data->insertElement($pos++, $twofa_form);
			}
			else { // The user may opt in using GA.
				$secret = $this->twofactor_getSecret();
				if ($secret != '') { // A system-wide secret exists					
					$event->data->insertElement($pos++, '<figure><figcaption>'.$this->getLang('twofactor_scanwithga').'</figcaption>');
					$data = $this->twofactor_generateQRCodeData($USERINFO['mail'], $secret);			
					$event->data->insertElement($pos++, '<img src="'.$data.'" alt="'.$this->getLang('twofactor_scanwithga').'" />');
					$event->data->insertElement($pos++, '</figure>');
					if (!$this->attribute->exists("twofactor","seenqrcode")){
						$event->data->insertElement($pos++, '<span>'.$this->getLang('twofactor_verifyga').'</span>');
						$twofa_form = form_makeTextField('verifyga', '', $this->getLang('twofactor_codefromga'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
						$event->data->insertElement($pos++, $twofa_form);
					}
					else {
						$event->data->insertElement($pos++, $this->getLang('twofactor_gaready'));
					}
				}
				else { // The user can generate a personal secret; no system secret exists.
					//Provide a checkbox to create a personal secret.
					$twofa_form = form_makeCheckboxField('makegasecret', '1', $this->getLang('twofactor_makegasecret'), '', 'block');
					$event->data->insertElement($pos++, $twofa_form);
				}
			}

		}
		// Verify phone number if used.
		if ($optstate == 'in' && $this->getConf("useotp") === 1 && $this->getConf("otpmethod") != 'email') {
			// Provide an input for the phone number.
			$twofa_form = form_makeTextField('phone', $this->attribute->get("twofactor","phone"), $this->getLang('twofactor_phone'), '', 'block', array('size'=>'50'));
			$event->data->insertElement($pos++, $twofa_form);
			// If using an SMS email gateway, ask for the cellphone provider.
			if ($this->getConf("otpmethod") == 'smsgateway') {
				$provider = $this->attribute->get("twofactor","provider");
				$providers = array_keys($this->twofactor_getProviders());
				$twofa_form = form_makeListboxField('provider', $providers, $provider, $this->getLang('twofactor_provider'), '', 'block');
				$event->data->insertElement($pos++, $twofa_form);
			}

			// If the phone number has not been verified, then do so here.
			if ($this->attribute->exists("twofactor","phone") && !$this->attribute->exists("twofactor","seensms")) {
				// Get the existing OTP if present.
				$otppresent = $this->attribute->exists("twofactor","otp");
				if ($otppresent) {
					list($myotp, $expires) = $this->attribute->get("twofactor","otp");
				}
				// If there is no OTP or it has expired, resend it.
				if (!$otppresent || time() > $expires) {
					$this->twofactor_send_otp();
				}
				// Render the HTML to prompt for the verification/activation OTP.
				$event->data->insertElement($pos++, '<span>'.$this->getLang('twofactor_smsnotice').'</span>');
				$twofa_form = form_makeTextField('verifysms', '', $this->getLang('twofactor_otplogin'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
				$event->data->insertElement($pos++, $twofa_form);
				$event->data->insertElement($pos++, form_makeCheckboxField('resend', '1', $this->getLang('btn_resend'),'','block'));
			}
			
			if ($this->attribute->exists("twofactor","phone")) {
				$twofa_form = form_makeCheckboxField('killsms', '1', $this->getLang('twofactor_killsms'), '', 'block');
				$event->data->insertElement($pos++, $twofa_form);
			}

		}
    }

    /**
     * Sets a flag if we are working with the profile. This ensures that extra data is only updated when the profile is being worked on.
     */
    function twofactor_verify_in_profile(&$event, $param) {
		// Check if this is the condition we are trying to monitor.
		$this->modifyProfile = $event->data == 'profile';
		return true;
	}

    /**
     * Action process redirector.  If logging out, processes the logout
     * function.  If visiting the profile, sets a flag to confirm that the
     * profile is being viewed in order to enable OTP attribute updates.
     */
	function twofactor_action_process_handler(&$event, $param){
		if ($event->data == 'logout') {
			$this->twofactor_logout();
			return true;
		}
		elseif ($event->data == 'profile') {
			return $this->twofactor_verify_in_profile($event, $param);
		}
		return true;
	}

    /**
     * Logout this session from two factor authentication.  Purge any existing
     * OTP from the user's attributes.
     */
    function twofactor_logout() {
		if ($this->attribute) {
			$this->attribute->del("twofactor","otp");
		}
		unset($_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance']);
	}

    /**
     * See if the current session has passed two factor authentication.
     * @return bool - true if the session as successfully passed two factor
     *      authentication.
     */
    function twofactor_getClearance() {
		return isset($_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance'])  && $_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance'] === true;
	}

    /**
     * Flags this session as having passed two factor authentication.
     * @return bool - returns true on successfully granting two factor clearance.
     */
    function twofactor_grantClearance() {
		// Purge the otp code as a security measure.
		$this->attribute->del("twofactor","otp");
		return $_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance']=true;
	}

    /**
     * If the conditions are right, process any updates to this module's attributes.
     */
    function twofactor_process_changes(&$event, $param) {
		// If the plugin is disabled, then exit.
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }
		// If this is a modify event that succeeded, we are ok.
		if ($event->data['type'] == 'modify' && in_array($event->data['modification_result'], array(true, 1)) && $this->modifyProfile) {
			$changed = false;
			global $INPUT, $USERINFO;
			// Process opt in/out.
			if ($this->getConf("optinout") != 'mandatory') {
				$oldoptinout = $this->attribute->get("twofactor","state") === 'in'?'in':'out';
				$optinout = $INPUT->bool('optinout', false)?'in':'out';
				if ($oldoptinout != $optinout) {
					$this->attribute->set("twofactor","state", $optinout);
					$changed = true;
				}
			}
			// Update GA settings.
			if ($this->getConf("usega") == 1) {
				$ga = new PHPGangsta_GoogleAuthenticator();
				$oldmysecret = $this->attribute->get("twofactor","secret", $success);
				if ($INPUT->bool('killgasecret', false)) {
					$this->attribute->del("twofactor","secret");
					// Also delete the seenqrcode attribute.  Otherwise the system will still expect the user to login with GA.
					$this->attribute->del("twofactor","seenqrcode");
					$changed = true;
				}
				if ($INPUT->bool('makegasecret', false) && $success == false) { // Only make a code if one is not set.
					$mysecret = $ga->createSecret();
					if ($this->attribute->set("twofactor","secret", $mysecret)== false) {
						msg("TwoFactor: Error setting secret.", -1);
					}
					$changed = true;
				}
				$otp = $INPUT->str('verifyga', '');
				if ($otp) { // The user will use GA.
					$expiry = $this->getConf("gaexpiry");
					$secret = $this->twofactor_getSecret(); // We only get here if there will not be a user secret.
					$checkResult = $ga->verifyCode($secret, $otp, $expiry);
					// If the code works, then flag this account to use GA.
					if ($checkResult == false) {
						msg($this->getLang('twofactor_failedgasetup'), -1);
					}
					else {
						if ($this->attribute->set("twofactor","seenqrcode", true)== false) {
							msg("TwoFactor: Error setting seenqrcode.", -1);
						}
						else {
							msg($this->getLang('twofactor_passedgasetup'), 1);
							// If the user was not granted clearance before, do that now and redirect to 'show'.
							if (!$this->twofactor_getClearance()) {
								$this->twofactor_grantClearance();
								global $ACT;
								$ACT = 'show';
							}
							$changed = true;
						}
					}					
				}
			}
			//Update OTP settings.
			if ($this->getConf("useotp") == 1) {
				$oldphone = $this->attribute->get("twofactor","phone", $success);
				$phone = $INPUT->str('phone', '');
				if ($phone != $oldphone) {
					if ($this->attribute->set("twofactor","phone", $phone)== false) {
						msg("TwoFactor: Error setting phone.", -1);
					}
					// Delete the verification for the phone number if it was changed.
					$this->attribute->del("twofactor", "seensms");
					$changed = true;
				}
				
				$oldprovider = $this->attribute->get("twofactor","provider", $success);
				$provider = $INPUT->str('provider', '');
				if ($this->getConf("otpmethod") == 'smsgateway' && $this->attribute->exists("twofactor","phone") &&$provider != $oldprovider) {
					if ($this->attribute->set("twofactor","provider", $provider)== false) {
						msg("TwoFactor: Error setting provider.", -1);
					}
					// Delete the verification for the phone number if the carrier was changed.
					$this->attribute->del("twofactor", "seensms");
					$changed = true;
				}

				if ($INPUT->bool('killsms', false)) {
					$this->attribute->del("twofactor","phone");
					$this->attribute->del("twofactor","provider");
					// Also delete the seensms attribute.  Otherwise the system will still expect the user to login with OTP.
					$this->attribute->del("twofactor","seensms");
					$changed = true;
				}

				$otp = $INPUT->str('verifysms', '');
				if ($otp) { // The user will use SMS.
					$otppresent = $this->attribute->exists("twofactor","otp");
					if ($otppresent) {
						list($myotp, $expires) = $this->attribute->get("twofactor","otp");
					}					
					if ($otp !== $myotp || time() > $expires) {
						msg($this->getLang('twofactor_failedsmssetup'), -1);
					}
					else {
						// The user's ability to process OTP has been confirmed.
						if ($this->attribute->set("twofactor","seensms", true)== false) {
							msg("TwoFactor: Error setting seensms.", -1);
						}
						else {
							msg($this->getLang('twofactor_passedsmssetup'), 1);
							// Remove used OTP.
							$this->attribute->del("twofactor","otp");
							// If the user was not granted clearance before, do that now and redirect to 'show'.
							if (!$this->twofactor_getClearance()) {
								$this->twofactor_grantClearance();
								global $ACT;
								$ACT = 'show';
							}
							$changed = true;
						}
					}
				}				

				if ($INPUT->bool('resend', false)) {
					$this->twofactor_send_otp();
				}
			}

			// Update change status if changed.
			if ($changed) {
				msg($this->getLang('twofactor_updated'), 1);
				// TODO: get the profile page to return if any two factor changes are made.
			}
		}
		return ;
	}

    /**
     * Handles the authentication check. Screens Google Authenticator OTP, if available.
     */
    function twofactor_before_auth_check(&$event, $param) {
		global $ACT;
		
		// If two factor is disabled, then there is nothing to do here.
		if ($this->getConf("enable") !== 1) return; 
		
		// Only operate if this is a login.
		//if ($ACT !== 'login') return;
		
		// If there is no supplied username, then there is nothing to check at this time.
		if (!$event->data['user']) { return; }
		
		$user = $_SERVER['REMOTE_USER'] != '' ? $_SERVER['REMOTE_USER'] : $event->data['user'];
		// If there is no active user name, then purge our two factor clearance token.
		if ($_SERVER['REMOTE_USER'] == '') {
			$this->twofactor_logout();
		}

		// If the user still has clearance, then we can skip this.
		$twofactor = $this->twofactor_getClearance();		
		if ($twofactor) { return; }
		
		// GA is available if two factor is enabled, ga is enabled, and the user has verified that GA is setup on their device.
		$gaavailable = $this->getConf("usega") === 1 && $this->attribute->exists("twofactor","seenqrcode", $user) === true;
		$otpmethod = $this->getConf("otpmethod");
		$otpenabled = $this->getConf("useotp") === 1;
		$otpavailable = $otpenabled && ($otpmethod === 'email' || $this->attribute->exists("twofactor","seensms", $user));
		if ($user != '' && $gaavailable){ // GA two factor not completed, but available.
			global $INPUT;
			$otp = $INPUT->str('otp');
			if ($otp) {  // A GA OTP was supplied.
                $ga = new PHPGangsta_GoogleAuthenticator();
				$expiry = $this->getConf("gaexpiry");
				$secret = $this->twofactor_getSecret($user);
                $checkResult = $ga->verifyCode($secret, $otp, $expiry);
				// If the code fails, then revoke the login.
				if ($checkResult == false) {
					global $lang;
					msg($lang['badlogin'], -1);
					$event->preventDefault();
					return;
				}
				// The OTP code was valid.
				$this->twofactor_grantClearance();
				return;
			}
			else { // No GA OTP was supplied.
				// If the user has an alternative two factor configured, then allow it to be used.
				// Otherwise fail.				
				if (!$otpavailable) {
					// There is no other two factor option, and this user did not supply a GA OTP code.
					// Revoke the logon.
					msg($this->getLang('twofactor_mustusega'), -1);
					$event->preventDefault();
					return;
				}
			}					
		}		 
		
		// Check to see if the user has not configured two factor authentication yet.
		// If there is no seenqrcode attribute, then the user has not had a chance to configure GA.
		// If there is no phone attribute and the otpmode is not email, then the user has not configured otp.
		if (!$gaavailable && !$otpavailable) {
			// If the user has not configured either option and two factor is not mandatory, then grant clearance.				
			if ($this->getConf("optinout") != 'mandatory') {
				//There is no two factor configured for this user and it is not mandatory. Give clearance.
				$this->twofactor_grantClearance();
			}	
			// Otherwise this is mandatory.  Stop the default action, and set ACT to profile so the user can configure their two factor.
			$ACT = 'profile';
		}
		
    }

    /**
     * @param $event
     * @param $param
     */
    function twofactor_after_auth_check(&$event, $param) {
		// If two factor is disabled, then there is nothing to do here.
		if ($this->getConf("enable") !== 1) return; 
		
		// Skip this if not logged in or already two factor authenticated.
		$twofactor = $this->twofactor_getClearance();
		if ($_SERVER['REMOTE_USER'] == '' || $twofactor === true) { return; }

		global $INPUT, $ACT;
		// If the user is trying to logout, then we will allow this.
		if ($ACT == 'logout') { return; }

		$optinout = $this->getConf("optinout");
		$optstate = $this->attribute ? $this->attribute->get("twofactor","state") : '';
		$gaavailable = $this->getConf("usega") === 1 && $this->attribute->exists("twofactor","seenqrcode");
		$otpmethod = $this->getConf("otpmethod");
		$otpenabled = $this->getConf("useotp") === 1;
		$otpavailable = $otpenabled && ($otpmethod === 'email' || $this->attribute->exists("twofactor","seensms"));
		$enable = $this->getConf("enable") && // The module is enabled AND...
			((!$optinout === 'optin' || $optstate === 'in') // Opt-in is off OR the user has opted in
			|| // OR...
			($optinout === 'optout' && $optstate !== 'out') // Opt-out is on AND the user has not opted out
			|| // OR...
			$optinout === 'mandatory'); // User must participate.
		if ($enable) {
			
			// Check to see if the user has not configured two factor authentication yet.
			// If there is no seenqrcode attribute, then the user has not had a chance to configure GA.
			// If there is no phone attribute and the otpmode is not email, then the user has not configured otp.	
			
			if (!$gaavailable && !$otpavailable && $ACT != 'logout') {
				// Two factor is mandatory, but not set up.
				// Redirect to the profile page.	
				$ACT = 'profile';
				return;
			}
			
			// See if the user is quitting OTP.  We don't call it logoff because we don't want the user to think they are logged in!
			// This has to be checked before the template is started.
			if ($INPUT->has('otpquit')) {
				// Redirect to logoff.
				$event->preventDefault();
				$event->stopPropagation();
				$ACT = 'logout';
				return;
			}

			// If a OTP has been submitted by the user, then verify the OTP.
			// If verified, then grant clearance and continue normally.
			$otp = $INPUT->str('otpcode');
			$otppresent = $this->attribute->exists("twofactor","otp");
			if ($otppresent) {
				list($myotp, $expires) = $this->attribute->get("twofactor","otp");
			}
			if ($otp && !$INPUT->has('resend')) {
				if ($otp != $myotp || time() > $expires) {
					// The OTP is wrong or expired.  Inform the user.
					msg($this->getLang('twofactor_invalidotp') ,-1);
				}
				else {
					// The OTP was valid.  Flag past this block.
					$this->twofactor_grantClearance();
					return;
				}
			}
			
			// Check if the user asked to generate and resend the OTP.
			if ($INPUT->has('resend')) {
				// At this point, try to send the OTP.
				$this->twofactor_send_otp();
			}
		}
	}
	
	/**
     * Handles the email and text OTP options.
	 * NOTE: The user will be technically logged in at this point.  This module will rewrite the
	 * page with the prompt for the OTP until validated or the user logs out.
     */
    function twofactor_prompt_otp(&$event, $param) {
		// Skip this if not logged in or already two factor authenticated.
		$twofactor = $this->twofactor_getClearance();
		if ($_SERVER['REMOTE_USER'] == '' || $twofactor === true) { return; }
		
		// Setup some availability variables.
		$optinout = $this->getConf("optinout");
		$optstate = $this->attribute ? $this->attribute->get("twofactor","state") : '';
		$gaavailable = $this->getConf("usega") === 1 && $this->attribute->exists("twofactor","seenqrcode");
		$otpmethod = $this->getConf("otpmethod");
		$otpenabled = $this->getConf("useotp") === 1;
		$otpavailable = $otpenabled && ($otpmethod === 'email' || $this->attribute->exists("twofactor","seensms"));
		$enable = $this->getConf("enable") && // The module is enabled AND...
			((!$optinout === 'optin' || $optstate === 'in') // Opt-in is off OR the user has opted in
			|| // OR...
			($optinout === 'optout' && $optstate !== 'out')) // Opt-out is on AND the user has not opted out
			|| // OR...
			$optinout === 'mandatory'; // User must participate.
		if ($enable){ // User logged in, two factor required, but not completed.

			// If we are here, the user has configured some sort two factor mechanism.  
			// At a minimum, if they had GA setup but not OTP, then their login would have failed.
			// That means that we will try to process the login via OTP.
			// If the user cannot sign in using OTP, see if they need to be directed to the profile screen 
			// to setup two factor.
			global $ACT;
			if (!$otpavailable && !$gaavailable && $ACT == 'profile') {
				// We are heading to the profile page because nothing is setup.  Good.
				return;
			}
			
			// Ensure the OTP exists and is still valid. If we need to, send a OTP.
			$otppresent = $this->attribute->exists("twofactor","otp");
			if ($otppresent) {
				list($myotp, $expires) = $this->attribute->get("twofactor","otp");
			}
			if (!$otppresent || time() > $expires) {
				// At this point, try to send the OTP.
				$this->twofactor_send_otp();
			}

			// Generate the form to login.
			// If we are here, then only provide options to accept the OTP or to logout.		
    		global $lang;
			$form = new Doku_Form(array('id' => 'otp_setup'));
			$form->startFieldset($this->getLang('twofactor_otplogin'));
			$form->addElement(form_makeTextField('otpcode', '', $this->getLang('twofactor_otplogin'), '', 'block', array('size'=>'50', 'autocomplete'=>'off')));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_submit')));
			$form->addElement(form_makeTag('br'));
			$form->addElement(form_makeTag('br'));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_resend'), array('name'=>'resend')));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_quit'), array('name'=>'otpquit')));
			$form->endFieldset();
			$output = '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
			$event->data = '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
		}
    }

    /**
     * Transmits a One-Time Password (OTP) using the wiki-configured method.
     * This may be to the user's email address, sending an email to the user's
     * configured email to SMS gateway, or via a SMS appliance.
     * @return bool - Success of transmission.
     */
    function twofactor_send_otp() {
		// Generate the OTP code.
		$characters = '0123456789';
		$otp = '';
		for ($index = 0; $index < $this->getConf('otplength'); ++$index) {
			$otp .= $characters[rand(0, strlen($characters) - 1)];
		}
		// Create the message.
		$message = str_replace('$otp', $otp, $this->getConf('otpcontent'));
		// Pick the delivery method.
		$otpmethod = $this->getConf("otpmethod");
		if ($otpmethod == 'smsappliance') { // If we are using an SMS appliance
			$number = $this->attribute->get("twofactor","phone", $success);
			if (!$success) {
				// If there is no phone number, then fail.
				return false;
			}
			$url = str_replace('$phone', $number, $this->getConf('otpurl'));
			$url = str_replace('$msg', rawurlencode($message), $url);
			// Deliver the message and capture the results.
			$result = file_get_contents($url);
			// TODO: How do we verify success?
		}
		else { //If we are not using an appliance
			// Import conf to manage html emails and get the wiki name.
			global $conf;
		if ($otpmethod == 'email') { // Send to this user's email address
				global $USERINFO;
				$to = $USERINFO['mail'];
			}
			else { // Send to this user's phone
				// Disable HTML for text messages.				
				$conf['htmlmail'] = 0;			
				$number = $this->attribute->get("twofactor","phone");
				if (!$number) {
					msg("TwoFactor: User has not defined a phone number.  Failing.", -1);
					// If there is no phone number, then fail.
					return false;
				}
				$gateway = $this->attribute->get("twofactor","provider");
				$providers = $this->twofactor_getProviders();
				if (array_key_exists($gateway, $providers)) {
					$to = "{$number}@{$providers[$gateway]}";
				}
				else {
					$to = '';
				}
			}
			if (!$to) {
				msg("TwoFactor: Unable to define To field for email.  Failing.", -1);
				// If there is no recipient address, then fail.
				return false;
			}
			// Create the email object.
			$mail = new Mailer();
			$subject = $conf['title'].' login verification';
			$mail->to($to);
			$mail->cc('mwilmes@avc.edu');
			$mail->subject($subject);
			$mail->setText($message);			
			$result = $mail->send();
			msg($message, 0);
		}
		// Store the OTP code and the timestamp the OTP expires at.
		$this->attribute->set("twofactor","otp", array($otp, time() + $this->getConf('otpexpiry') * 60));
		return true;
	}

    /**
     * Provide the Google Authenticator secret to use for this user. If set
     * globally, that will override any per-user secret.  If not set globally
     * or per-user, returns the empty string.
     * @param string $user
     * @return string
     */
    function twofactor_getSecret($user = null) {
		$secret = $this->getConf("gasecret");
		if ($secret == '') {
			$secret = $this->attribute->get("twofactor","secret", $success, $user);
			if (!$success) {
				$secret == '';
			}
		}
		return $secret;
	}

    /**
     * Produce an array of SMS gateway email domains with the keys as the
     * cellular providers.  Reads the gateway.txt file to generate the list.
     * @return array - keys are providers, values are the email domains used
     *      to email an SMS to a phone user.
     */
    function twofactor_getProviders() {
		$filename = dirname(__FILE__).'/gateway.txt';
		$providers = array();
		$contents = explode("\n", io_readFile($filename));		
		foreach($contents as $line) {
			if (strstr($line, '@')) {
				list($provider, $domain) = explode("@", trim($line), 2);
				$providers[$provider] = $domain;
			}
		}
		return $providers;
	}

    /**
     * Generates the QR Code used by Google Authenticator and produces a data
     * URI for direct insertion into the HTML source.
     * @param $name - The email address fo the user
     * @param $secret - The secret hash used to seed the otp formula
     * @return string - a complete data URI to be placed in an img tag's src
     *      attribute.
     */
    function twofactor_generateQRCodeData($name, $secret) {
		$url = 'otpauth://totp/'.$name.'?secret='.$secret;
		// Capture PNG image for embedding into HTML.
		ob_start();
		// NOTE: the @ is required to supress output errors when trying to get 
		// the PNG data from the output buffer.
		@QRcode::png($url);
		$image_data = ob_get_contents();
		ob_end_clean();			
		// Convert to data URI.
		return "data:image/png;base64," . base64_encode($image_data);
	}
}
