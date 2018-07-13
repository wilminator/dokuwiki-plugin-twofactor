<?php
// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();
/**
 * Two Factor Action Plugin
 *
 * @author Mike Wilmes mwilmes@avc.edu
 * Big thanks to Daniel Popp and his Google 2FA code (authgoogle2fa) as a
 * starting reference.
 *
 * Overview:
 * The plugin provides for two opportunities to perform two factor
 * authentication. The first is on the main login page, via a code provided by
 * an external authenticator. The second is at a separate prompt after the
 * initial login. By default, all modules will process from the second login,
 * but a module can subscribe to accepting a password from the main login when
 * it makes sense, because the user has access to the code in advance.
 *
 * If a user only has configured modules that provide for login at the main
 * screen, the code will only be accepted at the main login screen for
 * security purposes.
 *
 * Modules will be called to render their configuration forms on the profile
 * page and to verify a user's submitted code. If any module accepts the
 * submitted code, then the user is granted access.
 *
 * Each module may be used to transmit a message to the user that their
 * account has been logged into. One module may be used as the default
 * transmit option. These options are handled by the parent module.
 */
// Load the authmod class. This will facilitate loading in child modules.
require_once(dirname(__FILE__).'/authmod.php');
// Create a definition for a 2FA cookie.
define('TWOFACTOR_COOKIE', '2FA'.DOKU_COOKIE);
class action_plugin_twofactor extends DokuWiki_Action_Plugin {
	public $success = false;
	private $attribute = null;
	private $tokenMods = null;
	private $otpMods = null;
    private $setTime = false;
	public function __construct() {
		$this->loadConfig();
		// Load the attribute helper if GA is active or not requiring use of email to send the OTP.
		$requireAttribute = $this->getConf("enable") === 1;
		$this->attribute = $requireAttribute ? $this->loadHelper('attribute', 'TwoFactor depends on the Attribute plugin, but the Attribute plugin is not installed!') : null;
		// Now figure out what modules to load and load them.
		$available = Twofactor_Auth_Module::_listModules();
		$allmodules = Twofactor_Auth_Module::_loadModules($available);
		$failed = array_diff($available, array_keys($allmodules));
		if (count($failed) > 0) {
			msg('At least one loaded module did not have a properly named class.' . ' ' . implode(', ', $failed), -1);
		}
		$this->modules =array_filter($allmodules, function($obj) {return $obj->getConf('enable') == 1;});
		// Sanity check.
		$this->success = (!$requireAttribute || ($this->attribute && $this->attribute->success)) && count($this->modules) > 0;
		}
    /**
     * Registers the event handlers.
     */
    public function register(Doku_Event_Handler $controller)
    {
        if($this->getConf("enable") === 1 && $this->success) {
			$firstlogin = false;
			foreach ($this->modules as $mod) {
				$firstlogin |= $mod->canAuthLogin();
			}
			if ($firstlogin) {
				$controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'twofactor_login_form');
			}
			// Adds our twofactor profile to the user tools.
            $controller->register_hook('TEMPLATE_USERTOOLS_DISPLAY', 'BEFORE', $this, 'twofactor_usertools_action');
			// For newer DokuWiki this adds our twofactor profile to the user menu.
            $controller->register_hook('MENU_ITEMS_ASSEMBLY', 'AFTER', $this, 'twofactor_menu_action');
			// Manage action flow around the twofactor authentication requirements.
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'twofactor_action_process_handler', null, -999999);
			// Handle the twofactor login and profile actions.
            $controller->register_hook('TPL_ACT_UNKNOWN', 'BEFORE', $this, 'twofactor_handle_unknown_action');
            $controller->register_hook('TPL_ACTION_GET', 'BEFORE', $this, 'twofactor_get_unknown_action');
			// If the user supplies a token code at login, checks it before logging the user in.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'BEFORE', $this, 'twofactor_before_auth_check', null, -999999);
			// Atempts to process the second login if the user hasn't done so already.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'twofactor_after_auth_check');
            $this->log('register: Session: '.print_r($_SESSION, true), self::LOGGING_DEBUGPLUS);
        }
    }
	public function twofactor_usertools_action(&$event, $param) {
		global $INPUT;
		$this->log('twofactor_usertools_action: start', self::LOGGING_DEBUG);
		if($INPUT->server->has('REMOTE_USER')) {
            $menuitem = tpl_action('twofactor_profile', true, 'li', true);
            array_unshift($event->data['items'], $menuitem);
		}
	}
    public function twofactor_menu_action(Doku_Event $event) {
        require_once(dirname(__FILE__).'/Profile2FA.php');
        global $INPUT;
		$this->log('twofactor_menu_action: start', self::LOGGING_DEBUG);
        // If this is not the user menu, then get out.
        if($event->data['view'] != 'user') return;
		if($INPUT->server->has('REMOTE_USER')) {
            // Create the new menu item
            $menuitem = new dokuwiki\Menu\Item\Profile2FA($this->getLang('btn_twofactor_profile'));
            // Find index of existing Profile menu item.
            for ($index = 0; $index > count($event->data['items']); $index++) {
                if ($event->data['items'][$index]->getType() === 'profile') {
                    break;
                }
            }
            array_splice($event->data['items'], $index + 1 , 0, [$menuitem]);
		}
    }
    /**
     * Handles the login form rendering.
     */
    public function twofactor_login_form(&$event, $param) {
		$this->log('twofactor_login_form: start', self::LOGGING_DEBUG);
		$twofa_form = form_makeTextField('otp', '', $this->getLang('twofactor_login'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
        $pos = $event->data->findElementByAttribute('type', 'submit');
        $event->data->replaceElement($pos-1, $twofa_form);
    }
    /**
     * Handles the profile form rendering.  Displays user manageable settings.
     */
    public function twofactor_profile_form(&$event, $param) {
		$this->log('twofactor_profile_form: start', self::LOGGING_DEBUG);
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }
		$optinout = $this->getConf("optinout");
		$optinvalue = $optinout == 'mandatory' ? 'in' : ($this->attribute ? $this->attribute->get("twofactor", "state") : '');
		$available = count($this->tokenMods) + count($this->otpMods) > 0;
		// If the user is being redirected here because of mandatory two factor, then display a message saying so.
		if (!$available && $optinout == 'mandatory') {
			msg($this->getLang('mandatory'), -1);
		}
        if ($this->attribute->get("twofactor", "state")=='' && $optinout =='optout') {
			msg($this->getLang('optout_notice'), 2);
        }
		global $USERINFO, $lang, $conf;
		$form = new Doku_Form(array('id' => 'twofactor_setup'));
		// Add the checkbox to opt in and out, only if optinout is not mandatory.
		$items = array();
		if ($optinout != 'mandatory') {
			if (!$this->attribute || !$optinvalue) {  // If there is no personal setting for optin, the default is based on the wiki default.
				$optinvalue = $this->getConf("optinout") == 'optout';
			}
			$items[] = form_makeCheckboxField('optinout', '1', $this->getLang('twofactor_optin'), '', 'block', $optinvalue=='in'?array('checked'=>'checked'):array());
		}
        // Add the notification checkbox if appropriate.
        if ($this->getConf('loginnotice') === 'user' && $optinvalue === 'in' && count($this->otpMods) > 0) {
            $loginnotice = $this->attribute ? $this->attribute->get("twofactor", "loginnotice") : false;
            $items[] = form_makeCheckboxField('loginnotice', '1', $this->getLang('twofactor_notify'), '', 'block', $loginnotice===true?array('checked'=>'checked'):array());
        }
        // Select a notification provider.
		if ($optinvalue == 'in') {
			// If there is more than one choice, have the user select the default.
			if (count($this->otpMods) > 1) {
				$defaultMod = $this->attribute->exists("twofactor", "defaultmod") ? $this->attribute->get("twofactor", "defaultmod") : null;
				$modList = array_merge(array($this->getLang('useallotp')), array_keys($this->otpMods));
				$items[] = form_makeListboxField('default_module', $modList, $defaultMod, $this->getLang('defaultmodule'), '', 'block');
			}
		}
		if (count($items) > 0) {
			$form->startFieldset($this->getLang('settings'));
			foreach ($items as $item) {
				$form->addElement($item);
			}
			$form->endFieldset();
		}
		// TODO: Make this AJAX so that the user does not have to keep clicking
		// submit them Update Profile!
		// Loop through all modules and render the profile components.
		if ($optinvalue == 'in') {
			$parts = array();
			foreach ($this->modules as $mod){
				if ($mod->getConf("enable") == 1) {
                    $this->log('twofactor_profile_form: processing '.get_class($mod).'::renderProfileForm()', self::LOGGING_DEBUG);
					$items = $mod->renderProfileForm();
					if (count($items) > 0) {
						$form->startFieldset($mod->getLang('name'));
						foreach ($items as $item) {
							$form->addElement($item);
						}
						$form->endFieldset();
					}
				}
			}
		}
		if ($conf['profileconfirm']) {
			$form->addElement('<br />');
			$form->startFieldset($this->getLang('verify_password'));
			$form->addElement(form_makePasswordField('oldpass', $lang['oldpass'], '', 'block', array('size'=>'50', 'required' => 'required')));
			$form->endFieldset();
		}
		$form->addElement('<br />');
		$form->addElement(form_makeButton('submit', '', $lang['btn_save']));
		$form->addElement('<a href="'.wl($ID, array('do'=>'show'), true, '&').'">'.$this->getLang('btn_return').'</a>');
		$form->addHidden('do', 'twofactor_profile');
		$form->addHidden('save', '1');
		echo '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
}
    /**
     * Action process redirector.  If logging out, processes the logout
     * function.  If visiting the profile, sets a flag to confirm that the
     * profile is being viewed in order to enable OTP attribute updates.
     */
	public function twofactor_action_process_handler(&$event, $param){
		global $USERINFO, $ID, $INFO, $INPUT;
		$this->log('twofactor_action_process_handler: start '.$event->data, self::LOGGING_DEBUG);
		// Handle logout.
		if ($event->data == 'logout') {
			$this->_logout();
			return;
		}
		// Handle main login.
		if ($event->data == 'login') {
            // To support loglog or any other module that hooks login checking for success,
            // Confirm that the user is logged in.  If not, then redirect to twofactor_login
            // and fail the login.
            if (!$this->get_clearance()){
                // Hijack this event.  We need to resend it after 2FA is done.
                $event->stopPropagation();
                // Send loglog an event to show the user logged in but needs OTP code.
                $log = array('message' => 'logged in, '.$this->getLang('requires_otp'), 'user' => $user);
                trigger_event('PLUGIN_LOGLOG_LOG',$log);
            }
			return;
		}
		// Check to see if we are heading to the twofactor profile.
		if ($event->data == 'twofactor_profile') {
			// We will be handling this action's permissions here.
			$event->preventDefault();
			$event->stopPropagation();
			// If not logged into the main auth plugin then send there.
			if (!$USERINFO) {
				$event->result = false;
				send_redirect(wl($ID, array('do'=>'login'), true, '&'));
				return;
			}
			// If not logged into twofactor then send there.
			if (!$this->get_clearance()) {
				$event->result = false;
				send_redirect(wl($ID, array('do'=>'twofactor_login'), true, '&'));
				return;
			}
			// Otherwise handle the action.
			$event->result = $this->_process_changes($event, $param);
			return;
		}
		// Check to see if we are heading to the twofactor login.
		if ($event->data == 'twofactor_login') {
            // Check if we already have clearance- just in case.
            if ($this->get_clearance()) {
                // Okay, this continues on with normal processing.
				return;
            }
			// We will be handling this action's permissions here.
			$event->preventDefault();
			$event->stopPropagation();
			// If not logged into the main auth plugin then send there.
			if (!$USERINFO) {
				$event->result = false;
				send_redirect(wl($ID, array('do'=>'login'), true, '&'));
				return;
			}
            if (count($this->otpMods) == 0) {
                $this->log('No available otp modules.',self::LOGGING_DEBUG);
                // There is no way to handle this login.
                msg($this->getLang('mustusetoken'), -1);
                $event->result = false;
				send_redirect(wl($ID, array('do'=>'logout'), true, '&'));
				return;
            }
            // Otherwise handle the action.
            $act = $this->_process_otp($event, $param);
			$event->result = true;
            if ($act) {
                send_redirect(wl($ID, array('do'=>$act), true, '&'));
            }
			return;
		}
		// See if this user has any OTP methods configured.
		$available = count($this->tokenMods) + count($this->otpMods) > 0;
        // Check if this user needs to login with 2FA.
        $mandatory = $this->getConf("optinout") == 'mandatory' && $INPUT->server->str('REMOTE_USER','');
        $not_opted_out = $this->attribute->get("twofactor", "state") == '' && $this->getConf("optinout") == 'optout';
        $must_login = $mandatory || $this->attribute->get("twofactor", "state") == 'in';
        $this->log('twofactor_action_process_handler: USERINFO: '.print_r($USERINFO, true),self::LOGGING_DEBUGPLUS);
        // Enforce login if user must login.
        if (!$this->get_clearance() && $must_login) {
            if (!in_array($event->data, array('login', 'twofactor_login'))) {
                // If not logged in then force to the login page.
                $event->preventDefault();
                $event->stopPropagation();
                $event->result = false;
                // If there are OTP generators, then use them.
                send_redirect(wl($ID, array('do'=>'twofactor_login'), true, '&'));
                return;
            }
            // Otherwise go to where we are told.
            return;
        }
        // Possible combination skipped- not logged in and 2FA is not requred for user {optout conf or (no selection and optin conf)}.
        // Check to see if updating twofactor is required.
        if (($mandatory || $not_opted_out) && !$available) {
            // We need to be going to the twofactor profile.
            // If we were setup, we would not be here in the code.
            $event->preventDefault();
            $event->stopPropagation();
            $event->result = false;
            // Send loglog an event to show the user aborted 2FA.
            $log = array('message' => 'logged in, '.$this->getLang('2fa_mandatory'), 'user' => $user);
            trigger_event('PLUGIN_LOGLOG_LOG',$log);
            send_redirect(wl($ID, array('do'=>'twofactor_profile'), true, '&'));
            return;
        }
		// Otherwise everything is good!
		return;
	}
	public function twofactor_handle_unknown_action(&$event, $param) {
		$this->log('twofactor_handle_unknown_action: start', self::LOGGING_DEBUG);
		if ($event->data == 'twofactor_profile') {
			$event->preventDefault();
			$event->stopPropagation();
			$event->result = $this->twofactor_profile_form($event, $param);
			return;
		}
		if ($event->data == 'twofactor_login') {
			$event->preventDefault();
			$event->stopPropagation();
			$event->result = $this->twofactor_otp_login($event, $param);
			return;
		}
	}
	public function twofactor_get_unknown_action(&$event, $param) {
		$this->log('start: twofactor_before_auth_check', self::LOGGING_DEBUG);
		switch($event->data['type']) {
			case 'twofactor_profile':
				$event->data['params'] = array('do' => 'twofactor_profile');
				// Inject text into $lang.
				global $lang;
				$lang['btn_twofactor_profile'] = $this->getLang('btn_twofactor_profile');
				$event->preventDefault();
				$event->stopPropagation();
				$event->result = false;
				break;
		}
	}
    /**
     * Logout this session from two factor authentication.  Purge any existing
     * OTP from the user's attributes.
     */
    private function _logout() {
        global $conf, $INPUT;
		$this->log('_logout: start', self::LOGGING_DEBUG);
		$this->log(print_r(array($_SESSION, $_COOKIE), true), self::LOGGING_DEBUGPLUS);
        // No need to do this as long as no Cookie or session for login is present!
        if (empty($_SESSION[DOKU_COOKIE]['twofactor_clearance']) && empty($_COOKIE[TWOFACTOR_COOKIE])) {
            $this->log('_logout: quitting, no cookies', self::LOGGING_DEBUG);
            return;
        }
        // Audit log.
        $this->log("2FA Logout: ".$INPUT->server->str('REMOTE_USER', $_REQUEST['r']), self::LOGGING_AUDIT);
		if ($this->attribute) {
            // Purge outstanding OTPs.
            $this->attribute->del("twofactor", "otp");
            // Purge cookie and session ID relation.
            $key = $_COOKIE[TWOFACTOR_COOKIE];
            if (!empty($key) && substr($key,0,3) != 'id.') {
                $id = $this->attribute->del("twofactor", $key);
            }
            // Wipe out 2FA cookie.
            $this->log('del cookies: '.TWOFACTOR_COOKIE.' '.print_r(headers_sent(), true), self::LOGGING_DEBUGPLUS);
            $cookie    = '';
            $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
            $time      = time() - 600000; //many seconds ago
            setcookie(TWOFACTOR_COOKIE, $cookie, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
            unset($_COOKIE[TWOFACTOR_COOKIE]);
            // Just in case, unset the setTime flag so attributes will be saved again.
            $this->setTime = false;
		}
		// Before we get here, the session is closed. Reopen it to logout the user.
		if (!headers_sent()) {
			$session = session_status() != PHP_SESSION_NONE;
			if (!$session) { session_start(); }
			$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = false;
			unset($_SESSION[DOKU_COOKIE]['twofactor_clearance']);
			if (!$session) { session_write_close(); }
		}
		else {
			msg("Error! You have not been logged off!!!", -1);
		}
	}
    /**
     * See if the current session has passed two factor authentication.
     * @return bool - true if the session as successfully passed two factor
     *      authentication.
     */
    public function get_clearance($user=null) {
        global $INPUT;
        $this->log("get_clearance: start", self::LOGGING_DEBUG);
        $this->log("User:".$INPUT->server->str('REMOTE_USER', null), self::LOGGING_DEBUGPLUS);
        # Get and correct the refresh expiry.
        # At least 5 min, at most 1440 min (1 day).
        $refreshexpiry = min(max($this->getConf('refreshexpiry'), 5) ,1400) * 60;
        # First check if we have a key.  No key === no login.
        $key = $_COOKIE[TWOFACTOR_COOKIE];
        if (empty($key)) {
            $this->log("get_clearance: No cookie.", self::LOGGING_DEBUGPLUS);
            return false;
        }
        # If the key is not valid, logout.
        if (substr($key,0,3) != 'id.') {
            $this->log("get_clearance: BAD cookie.", self::LOGGING_DEBUGPLUS);
            // Purge the login data just in case.
            $this->_logout();
            return false;
        }
        # Load the expiry value from session.
        $expiry = $_SESSION[DOKU_COOKIE]['twofactor_clearance'];
        # Check if this time is valid.
        $clearance = (!empty($expiry) && $expiry + $refreshexpiry > time());
        if (!$clearance) {
            # First use this time to purge the old IDs from attribute.
            foreach(array_filter($this->attribute->enumerateAttributes("twofactor", $user), function ($key) {substr($key, 0, 3) == 'id.';}) as $attr) {
                if ($this->attribute->get("twofactor", $attr, $user) + $refreshexpiry < time()) {
                    $this->attribute->del("twofactor", $attr, $user);
                }
            }
            # Check if this key still exists.
            $clearance = $this->attribute->exists("twofactor", $key, $user);
            if ($clearance) {
                $this->log("get_clearance: 2FA revived by cookie. Expiry: ".print_r($expiry, true)." Session: ".print_r($_SESSION, true), self::LOGGING_DEBUGPLUS);
            }
        }
        if ($clearance && !$this->setTime) {
            $session = session_status() != PHP_SESSION_NONE;
            if (!$session) { session_start(); }
            $_SESSION[DOKU_COOKIE]['twofactor_clearance'] = time();
            if (!$session) { session_write_close();}
            $this->attribute->set("twofactor", $key, $_SESSION[DOKU_COOKIE]['twofactor_clearance'], $user);
            // Set this flag to stop future updates.
            $this->setTime = true;
            $this->log("get_clearance: Session reset. Session: ".print_r($_SESSION, true), self::LOGGING_DEBUGPLUS);
        }
        elseif (!$clearance) {
            // Otherwise logout.
            $this->_logout();
        }
		return $clearance;
	}
    /**
     * Flags this session as having passed two factor authentication.
     * @return bool - returns true on successfully granting two factor clearance.
     */
    private function _grant_clearance($user = null) {
        global $conf, $INPUT;
        $this->log("_grant_clearance: start", self::LOGGING_DEBUG);
        $this->log('2FA Login: '.$INPUT->server->str("REMOTE_USER",$user), self::LOGGING_AUDIT);
		// Purge the otp code as a security measure.
		$this->attribute->del("twofactor", "otp", $user);
		if (!headers_sent()) {
			$session = session_status() != PHP_SESSION_NONE;
			if (!$session) { session_start(); }
			$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = time();
			$_SESSION[DOKU_COOKIE]['twofactor_notify'] = true;
			if (!$session) { session_write_close(); }
		}
		else {
			msg("Error! You have not been logged in!!!", -1);
		}
        // Creating a cookie in case the session purges.
        $key = 'id.'.session_id();
        // Storing a timeout value.
        $this->attribute->set("twofactor", $key, $_SESSION[DOKU_COOKIE]['twofactor_clearance'], $user);
        // Set the 2FA cookie.
        $this->log('_grant_clearance: new cookies: '.TWOFACTOR_COOKIE.' '.print_r(headers_sent(), true), self::LOGGING_DEBUGPLUS);
        $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
        $time      = time() + 60 * 60 * 24 * 365; //one year
        setcookie(TWOFACTOR_COOKIE, $key, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
        $_COOKIE[TWOFACTOR_COOKIE] = $key;
		return !empty($_SESSION[DOKU_COOKIE]['twofactor_clearance']);
	}
    /**
     * Sends emails notifying user of successfult 2FA login.
     * @return mixed - returns true on successfully sending notification to all
     *     modules, false if no notifications were sent, or a number indicating
     *     the number of modules that suceeded.
     */
    private function _send_login_notification() {
        $this->log("_send_login_notification: start", self::LOGGING_DEBUG);
        // Send login notification.
        $module = $this->attribute->exists("twofactor", "defaultmod") ? $this->attribute->get("twofactor", "defaultmod") : null;
        $subject = $this->getConf('loginsubject');
        $time = date(DATE_RFC2822);
        $message = str_replace('$time', $time, $this->getConf('logincontent'));
        $result = $this->_send_message($subject, $message, $module);
        return $result;
	}
    /**
     * Handles the authentication check. Screens Google Authenticator OTP, if available.
	 * NOTE: NOT LOGGED IN YET. Attribute requires user name.
     */
    function twofactor_before_auth_check(&$event, $param) {
		global $ACT, $INPUT;
        $this->log("twofactor_before_auth_check: start $ACT", self::LOGGING_DEBUG);
        $this->log("twofactor_before_auth_check: Cookie: ".print_r($_COOKIE, true), self::LOGGING_DEBUGPLUS);
		// Only operate if this is a login.
		if ($ACT !== 'login') {
            return;
        }
		// If there is no supplied username, then there is nothing to check at this time.
		if (!$event->data['user']) { return; }
        $user = $INPUT->server->str('REMOTE_USER', $event->data['user']);
		// Set helper variables here.
		$this->_setHelperVariables($user);
		// If the user still has clearance, then we can skip this.
		if ($this->get_clearance($user)) { return; }
		// Allow the user to try to use login tokens, even if the account cannot use them.
		$otp = $INPUT->str('otp', '');
		if ($otp !== '') {
			// Check for any modules that support OTP at login and are ready for use.
			foreach ($this->tokenMods as $mod){
				$result = $mod->processLogin($otp, $user);
				if ($result) {
					// The OTP code was valid.
					$this->_grant_clearance($user);
                    // Send loglog an event to show the user logged in using a token.
                    $log = array('message' => 'logged in '.$this->getLang('token_ok'), 'user' => $user);
                    trigger_event('PLUGIN_LOGLOG_LOG',$log);
					return;
				}
			}
			global $lang;
			msg($lang['badlogin'], -1);
			$event->preventDefault();
            $event->result = false;
            // Send loglog an event to show the failure
            if (count($this->tokenMods) == 0) {
                $log = array('message' => 'failed '.$this->getLang('no_tokens'), 'user' => $user);
            } else {
                $log = array('message' => 'failed '.$this->getLang('token_mismatch'), 'user' => $user);
            }
            trigger_event('PLUGIN_LOGLOG_LOG',$log);
			return;
		}
		// No GA OTP was supplied.
		// If the user has no modules available, then grant access.
		// The action preprocessing will send the user to the profile if needed.
		$available = count($this->tokenMods) + count($this->otpMods) > 0;
        $this->log('twofactor_before_auth_check: Tokens:'.count($this->tokenMods).' Codes:'.count($this->otpMods)." Available:".(int)$available, self::LOGGING_DEBUGPLUS);
		if (!$available) {
            // The user could not authenticate if they wanted to.
            // Set this so they don't get auth prompted while setting up 2FA.
			$this->_grant_clearance($user);
			return;
		}
		// At this point, the user has a working module.
		// If the only working module is for a token, then fail.
		if (count($this->otpMods) == 0) {
			msg($this->getLang('mustusetoken'), -1);
			$event->preventDefault();
			return;
		}
		// The user is logged in to auth, but not into twofactor.
		// The redirection handler will send the user to the twofactor login.
		return;
    }
    /**
     * @param $event
     * @param $param
     */
    function twofactor_after_auth_check(&$event, $param) {
		global $ACT;
		global $INPUT;
        $this->log("twofactor_after_auth_check: start", self::LOGGING_DEBUG);
        // Check if the action was login.
		if ($ACT == 'login') {
            // If there *was* no one logged in, then purge 2FA tokens.
            if ($INPUT->server->str('REMOTE_USER', '') == '') {
                $this->_logout();
                // If someone *just* logged in, then fire off a log.
                if ($event->data['user']) {
                    // Send loglog an event to show the user logged in but needs OTP code.
                    $log = array('message' => 'logged in, '.$this->getLang('requires_otp'), 'user' => $event->data['user']);
                    trigger_event('PLUGIN_LOGLOG_LOG',$log);
                }
                return;
            }
		}
		// Update helper variables here since we are logged in.
		$this->_setHelperVariables();
        // If set, then send login notification and clear flag.
        if ($_SESSION[DOKU_COOKIE]['twofactor_notify'] == true){
            $result = $this->_send_login_notification();
            if ($result !== false) {
                unset($_SESSION[DOKU_COOKIE]['twofactor_notify']);
            }
        }
		return;
	}
    
	/* Returns action to take. */
	private function _process_otp(&$event, $param) {
		global $ACT, $ID, $INPUT;
        $this->log("_process_otp: start", self::LOGGING_DEBUG);
        // Get the logged in user.
		$user = $INPUT->server->str('REMOTE_USER');
		// See if the user is quitting OTP.  We don't call it logoff because we don't want the user to think they are logged in!
		// This has to be checked before the template is started.
		if ($INPUT->has('otpquit')) {
            // Send loglog an event to show the user aborted 2FA.
            $log = array('message' => 'logged off, '.$this->getLang('quit_otp'), 'user' => $user);
            trigger_event('PLUGIN_LOGLOG_LOG',$log);
			// Redirect to logout.
			return 'logout';
		}
		// Check if the user asked to generate and resend the OTP.
		if ($INPUT->has('resend')) {
			if	($INPUT->has('useall')) {
				$defaultMod = null;
			}
			else {
				$defaultMod = $this->attribute->exists("twofactor", "defaultmod") ? $this->attribute->get("twofactor", "defaultmod") : null;
			}
			// At this point, try to send the OTP.
			$mod = array_key_exists($defaultMod, $this->otpMods) ? $this->otpMods[$defaultMod] : null;
			$this->_send_otp($mod);
			return;
		}
		// If a OTP has been submitted by the user, then verify the OTP.
		// If verified, then grant clearance and continue normally.
		$otp = $INPUT->str('otpcode');
		if ($otp) {
			foreach ($this->otpMods as $mod){
				$result = $mod->processLogin($otp);
				if ($result) {
					// The OTP code was valid.
					$this->_grant_clearance();
                    // Send loglog an event to show the user passed 2FA.
                    $log = array('message' => 'logged in '.$this->getLang('otp_ok'), 'user' => $user);
                    trigger_event('PLUGIN_LOGLOG_LOG',$log);
                    /*
                    // This bypasses sending any further events to other modules for the login we stole earlier.
                    return 'show';
                    */
                    // This will trigger the login events again.  However, this is to ensure
                    // that other modules work correctly because we hijacked this event earlier.
					return 'login';
				}
			}
            // Send loglog an event to show the user entered the wrong OTP code.
            $log = array('message' => 'failed OTP login, '.$this->getLang('otp_mismatch'), 'user' => $user);
            trigger_event('PLUGIN_LOGLOG_LOG',$log);
			msg($this->getLang('twofactor_invalidotp'), -1);
		}
		return;
	}
    /**
     * Process any updates to two factor settings.
     */
    private function _process_changes(&$event, $param) {
		// If the plugin is disabled, then exit.
        $this->log("_process_changes: start", self::LOGGING_DEBUG);
		$changed = false;
		global $INPUT, $USERINFO, $conf, $auth, $lang, $ACT;
		if (!$INPUT->has('save')) {	return;	}
		// In needed, verify password.
		if($conf['profileconfirm']) {
			if(!$auth->checkPass($INPUT->server->str('REMOTE_USER'), $INPUT->post->str('oldpass'))) {
				msg($lang['badpassconfirm'], -1);
				return;
			}
		}
		// Process opt in/out.
		if ($this->getConf("optinout") != 'mandatory') {
			$oldoptinout = $this->attribute->get("twofactor", "state");
			$optinout = $INPUT->bool('optinout', false)?'in':'out';
			if ($oldoptinout != $optinout) {
				$this->attribute->set("twofactor", "state", $optinout);
				$changed = true;
			}
		}
		// Process notifications.
		if ($this->getConf("loginnotice") == 'user') {
			$oldloginnotice = $this->attribute->get("twofactor", "loginnotice");
			$loginnotice = $INPUT->bool('loginnotice', false);
			if ($oldloginnotice != $loginnotice) {
				$this->attribute->set("twofactor", "loginnotice", $loginnotice);
				$changed = true;
			}
		}
		// Process default module.
		$defaultmodule = $INPUT->str('default_module', '');
		if ($defaultmodule) {
            if ($defaultmodule === $this->getLang('useallotp')) {
                // Set to use ALL OTP channels.
                $this->attribute->set("twofactor", "defaultmod", null);
                $changed = true;
            }
            else {
                $useableMods = array();
                foreach($this->modules as $name=>$mod) {
                    if(!$mod->canAuthLogin() && $mod->canUse()) {
                        $useableMods[$mod->getLang("name")] = $mod;
                    }
                }
                if (array_key_exists($defaultmodule, $useableMods)) {
                    $this->attribute->set("twofactor", "defaultmod", $defaultmodule);
                    $changed = true;
                }
            }
		}
		// Update module settings.
		$sendotp = null;
		foreach ($this->modules as $name=>$mod){
            $this->log('_process_changes: processing '.get_class($mod).'::processProfileForm()', self::LOGGING_DEBUG);
			$result = $mod->processProfileForm();
            $this->log('_process_changes: processing '.get_class($mod).'::processProfileForm() == '.$result, self::LOGGING_DEBUGPLUS);
			// false:change failed  'failed':OTP failed  null: no change made
			$changed |= $result !== false && $result !== 'failed' && $result !== null;
			switch((string)$result) {
				case 'verified':
					// Remove used OTP.
					$this->attribute->del("twofactor", "otp");
					msg($mod->getLang('passedsetup'), 1);
					// Reset helper variables.
					$this->_setHelperVariables();
                    $this->log("2FA Added: ".$INPUT->server->str('REMOTE_USER', '').' '.get_class($mod), self::LOGGING_AUDIT);
					break;
				case 'failed':
					msg($mod->getLang('failedsetup'), -1);
					break;
				case 'otp':
					if (!$sendotp) {
						$sendotp = $mod;
					}
					break;
				case 'deleted':
                    $this->log("2FA Removed: ".$INPUT->server->str('REMOTE_USER', '').' '.get_class($mod), self::LOGGING_AUDIT);
					// Reset helper variables.
					$this->_setHelperVariables();
					break;
			}
		}
		// Send OTP if requested.
		if ($sendotp) {
			// Force the message since it will fail the canUse function.
			if ($this->_send_otp($sendotp, true)) {
				msg($sendotp->getLang('needsetup'), 1);
			}
			else {
				msg("Could not send message using ".get_class($sendotp), -1);
			}
		}
		// Update change status if changed.
		if ($changed) {
			msg($this->getLang('updated'), 1);
		}
		return true;
	}
	/**
     * Handles the email and text OTP options.
	 * NOTE: The user will be technically logged in at this point.  This module will rewrite the
	 * page with the prompt for the OTP until validated or the user logs out.
     */
    function twofactor_otp_login(&$event, $param) {
        $this->log("twofactor_otp_login: start", self::LOGGING_DEBUG);
		// Skip this if not logged in or already two factor authenticated.
		// Ensure the OTP exists and is still valid. If we need to, send a OTP.
		$otpQuery = $this->get_otp_code();
		if ($otpQuery == false) {
			$useableMods = array();
			foreach($this->modules as $name=>$mod) {
				if(!$mod->canAuthLogin() && $mod->canUse()) {
					$useableMods[$mod->getLang("name")] = $mod;
				}
			}
			$defaultMod = $this->attribute->exists("twofactor", "defaultmod") ? $this->attribute->get("twofactor", "defaultmod") : null;
			$mod = array_key_exists($defaultMod, $useableMods) ? $useableMods[$defaultMod] : null;
			$this->_send_otp($mod);
		}
		// Generate the form to login.
		// If we are here, then only provide options to accept the OTP or to logout.
		global $lang;
		$form = new Doku_Form(array('id' => 'otp_setup'));
		$form->startFieldset($this->getLang('twofactor_otplogin'));
		$form->addElement(form_makeTextField('otpcode', '', $this->getLang('twofactor_otplogin'), '', 'block', array('size'=>'50', 'autocomplete'=>'off')));
		$form->addElement(form_makeButton('submit', '', $this->getLang('btn_login')));
		$form->addElement(form_makeTag('br'));
		$form->addElement(form_makeCheckboxField('useall', '1', $this->getLang('twofactor_useallmods'), '', 'block'));
		$form->addElement(form_makeTag('br'));
		$form->addElement(form_makeButton('submit', '', $this->getLang('btn_resend'), array('name'=>'resend')));
		$form->addElement(form_makeButton('submit', '', $this->getLang('btn_quit'), array('name'=>'otpquit')));
		$form->endFieldset();
		echo '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
    }
    /**
     * Sends a message using configured modules.
     * If $module is set to a specific instance, that instance will be used to
	 * send the message. If not supplied or null, then all configured modules
     * will be used to send the message. $module can also be an array of
     * selected modules.
     * If $force is true, then will try to send the message even if the module
     * has not been validated.
     * @return array(array, mixed) - The first item in the array is an array
     *     of all modules that the message was successfully sent by.  The
     *     second item is true if successfull to all attempted tramsmission
	 *     modules, false if all failed, and a number of how many successes
	 *     if only some modules failed.
     */
    private function _send_message($subject, $message, $module = null, $force = false) {
        global $INPUT;
        $this->log("_send_message: start", self::LOGGING_DEBUG);
		if ($module === null) {
			$module = $this->otpMods;
		}
		if (!is_array($module)) {
			$module = array($module);
		}
		if (count($module)>=1) {
			$modulekeys = array_keys($module);
			$modulekey = $modulekeys[0];
			$modname = get_class($module[$modulekey]);
		}
		else {
			$modname = null;
		}
		// Attempt to deliver messages.
        $user = $INPUT->server->str('REMOTE_USER','*unknown*');
		$success = 0;
		$modname = array();
		foreach($module as $mod) {
			if ($mod->canTransmitMessage()) {
                $worked = $mod->transmitMessage($subject, $message, $force);
				if ($worked) {
					$success += 1;
					$modname[] = get_class($mod);
				}
                $this->log("Message ".($worked?'':'not ')."sent to $user via ".get_class($mod), self::LOGGING_AUDITPLUS);
			}
		}
		return array($modname, $success == 0 ? false : ($success == count($module) ? true : $success));
	}
    /**
     * Transmits a One-Time Password (OTP) using configured modules.
     * If $module is set to a specific instance, that instance will be used to
	 * send the OTP. If not supplied or null, then all configured modules will
	 * be used to send the OTP. $module can also be an array of selected
	 * modules.
     * If $force is true, then will try to send the message even if the module
     * has not been validated.
     * @return mixed - true if successfull to all attempted tramsmission
	 *     modules, false if all failed, and a number of how many successes
	 *     if only some modules failed.
     */
    private function _send_otp($module = null, $force = false) {
        $this->log("_send_otp: start", self::LOGGING_DEBUG);
		// Generate the OTP code.
		$characters = '0123456789';
		$otp = '';
		for ($index = 0; $index < $this->getConf('otplength'); ++$index) {
			$otp .= $characters[rand(0, strlen($characters) - 1)];
		}
		// Create the subject.
		$subject = $this->getConf('otpsubject');
		// Create the message.
		$message = str_replace('$otp', $otp, $this->getConf('otpcontent'));
        // Attempt to deliver the message.
        list($modname, $result) = $this->_send_message($subject, $message, $module, $force);
		// If partially successful, store the OTP code and the timestamp the OTP expires at.
		if ($result) {
			$otpData = array($otp, time() + $this->getConf('sentexpiry') * 60, $modname);
			if (!$this->attribute->set("twofactor", "otp", $otpData)){
				msg("Unable to record OTP for later use.", -1);
			}
		}
		return $result;
	}
    /**
     * Returns the OTP code sent to the user, if it has not expired.
     * @return mixed - false if there is no unexpired OTP, otherwise
	 *     array of the OTP and the modules that successfully sent it.
     */
	public function get_otp_code() {
        $this->log("get_otp_code: start", self::LOGGING_DEBUG);
		$otpQuery = $this->attribute->get("twofactor", "otp", $success);
		if (!$success) { return false; }
		list($otp, $expiry, $modname) = $otpQuery;
		if (time() > $expiry) {
			$this->attribute->del("twofactor", "otp");
			return false;
		}
		return array($otp, $modname);
	}
	private function _setHelperVariables($user = null) {
        $this->log("_setHelperVariables: start", self::LOGGING_DEBUGPLUS);
		// List all working token modules (GA, RSA, etc.).
		$tokenMods = array();
		foreach($this->modules as $name=>$mod) {
			if($mod->canAuthLogin() && $mod->canUse($user)) {
                $this->log('Can use '.get_class($mod).' for tokens', self::LOGGING_DEBUG);
				$tokenMods[$mod->getLang("name")] = $mod;
			} else {
                $this->log('Can NOT use '.get_class($mod).' for tokens', self::LOGGING_DEBUG);
            }
		}
		$this->tokenMods = $tokenMods;
		// List all working OTP modules (SMS, Twilio, etc.).
		$otpMods = array();
		foreach($this->modules as $name=>$mod) {
			if(!$mod->canAuthLogin() && $mod->canUse($user)) {
                $this->log('Can use '.get_class($mod).' for otp', self::LOGGING_DEBUG);
				$otpMods[$mod->getLang("name")] = $mod;
			} else {
                $this->log('Can NOT use '.get_class($mod).' for otp', self::LOGGING_DEBUG);
            }
		}
		$this->otpMods = $otpMods;
	}
    const LOGGING_AUDIT = 1;     // Audit records 2FA login and logout activity.
    const LOGGING_AUDITPLUS = 2; // Audit+ also records sending of notifications.
    const LOGGING_DEBUG = 3;     // Debug provides detailed workflow data.
    const LOGGING_DEBUGPLUS = 4; // Debug+ also includes variables passed to and from functions.
    public function log(string $message, int $level = 1) {
        // If the log level requested is below audit or greater than what is permitted in the configuration, then exit.
        if ($level < self::LOGGING_AUDIT || $level > $this->getConf('logging_level')) { return; }
        global $conf;
        // Always purge line containing "[pass]".
        $message = implode("\n", array_filter(explode("\n", $message), function ($x) { return !strstr($x, '[pass]'); }));
        // If DEBUGPLUS, then append the trace log.
        if ($level == self::LOGGING_DEBUGPLUS) {
            $e = new Exception();
            $message .= "\n".print_r(str_replace(DOKU_REL, '', $e->getTraceAsString()), true);
        }
        $logfile = $this->getConf('logging_path');
        $logfile = substr($logfile, 0, 1) == '/' ? $logfile : DOKU_INC. $conf['savedir'] .'/'. $logfile;
        io_lock($logfile);
        #open for append logfile
        $handle = @fopen($logfile, 'at');
        if ($handle) {
            $date = date(DATE_RFC2822);
            $IP = $_SERVER["REMOTE_ADDR"];
            $id = session_id();
            fwrite($handle, "$date,$id,$IP,$level,\"$message\"\n");
            fclose($handle);
        }
        #write "date level message"
        io_unlock($logfile);
    }
}