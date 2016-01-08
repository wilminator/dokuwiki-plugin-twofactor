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

class action_plugin_twofactor extends DokuWiki_Action_Plugin {
	public $success = false;
	private $attribute = null;
	private $tokenMods = null;
	private $otpMods = null;

	public function __construct() {
		$this->loadConfig();
		// Load the attribute helper if GA is active or not requiring use of email to send the OTP.
		$requireAttribute = $this->getConf("enable") === 1;
		$this->attribute = $requireAttribute ? $this->loadHelper('attribute', 'Attribute plugin required!') : null;		
		
		// Now figure out what modules to load and load them.				
		$available = Twofactor_Auth_Module::_listModules();		
		$allmodules = Twofactor_Auth_Module::_loadModules($available);
		$failed = array_diff($available, array_keys($allmodules));
		if (count($failed) > 0) {
			msg('At least one loaded module did not have a properly named class.' . ' ' . implode(', ', $failed), -1);
		}
		$this->modules =array_filter($allmodules, function($obj) {return $obj->getConf('enable') == 1;});
		//msg("Number of loaded twofactor modules: ".count($this->modules));

		// Sanity check.
		$this->success = (!$requireAttribute || ($this->attribute && $this->attribute->success)) && count($this->modules) > 0;
		}
	
	/**
	 * return some info
	 */
	public function getInfo(){
		return array(
            'author' => 'Mike Wilmes',
            'email'  => 'mwilmes@avc.edu',
            'date'   => '2015-09-04',
            'name'   => 'TwoFactor Plugin',
            'desc'   => 'This plugin provides for two factor authentication using extensible modules.',
            'url'    => 'http://www.dokuwiki.org/plugin:twofactor',
		);
	}

    /**
     * Registers the event handlers.
     */
    public function register(&$controller)
    {
        if($this->getConf("enable") === 1 && $this->success) {
			$firstlogin = false;
			foreach ($this->modules as $mod) {
				$firstlogin |= $mod->canAuthLogin();
			}
			if ($firstlogin) {
				$controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'twofactor_login_form', array());				
			}
			// Adds our twofactor profile to the user tools.
            $controller->register_hook('TEMPLATE_USERTOOLS_DISPLAY', 'BEFORE', $this, 'twofactor_usertools_action', array());
			// Provide user settings in profile.
            //$controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'twofactor_profile_form', array());
			// Ensures we are in the user profile.
			// Manage action flow around the twofactor authentication requirements.
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'twofactor_action_process_handler', array());
			// Handle the twofactor login and profile actions.
            $controller->register_hook('TPL_ACT_UNKNOWN', 'BEFORE', $this, 'twofactor_handle_unknown_action', array());
            $controller->register_hook('TPL_ACTION_GET', 'BEFORE', $this, 'twofactor_get_unknown_action', array());
			// Updates user settings. Ensures that the settings ceom from the profile using a flag passed by the above hook.
            $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'twofactor_process_changes', array());
			// If the user supplies a token code at login, checks it before logging the user in.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'BEFORE', $this, 'twofactor_before_auth_check', array());
			// Atempts to process the second login if the user hasn't done so already.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'twofactor_after_auth_check', array());
            // Ensures the user has passed the second login after logged in or displays a challenge screen.
			//$controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'twofactor_prompt_otp', array());TEMPLATE_' . strtoupper($toolsname) . '_DISPLAY
        }
    }
	
	public function twofactor_usertools_action(&$event, $param) {	
		global $INPUT;	
		if($INPUT->server->has('REMOTE_USER')&&$this->get_clearance()) {
            array_unshift($event->data['items'], tpl_action('twofactor_profile', true, 'li', true));
		}
	}

    /**
     * Handles the login form rendering.
     */
    public function twofactor_login_form(&$event, $param) {
		$twofa_form = form_makeTextField('otp', '', $this->getLang('twofactor_login'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
        $pos = $event->data->findElementByAttribute('type', 'submit');
        $event->data->replaceElement($pos-1, $twofa_form);
    }

    /**
     * Handles the profile form rendering.  Displays user manageable settings.
     */
    public function twofactor_profile_form(&$event, $param) {
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }

		$optinout = $this->getConf("optinout");
		$optstate = $optinout == 'mandatory' ? 'in' : ($this->attribute ? $this->attribute->get("twofactor","state") : '');
		$available = count($this->tokenMods) + count($this->otpMods) > 0;
		
		// If the user is being redirected here because of mandatory two factor, then display a message saying so.
		if (!$available && $optinout == 'mandatory') {
			msg($this->getLang('mandatory'), -1);
		}

		global $USERINFO, $lang, $conf;
		$form = new Doku_Form(array('id' => 'twofactor_setup'));
		// Add the checkbox to opt in and out, only if optinout is not mandatory.
		$items = array();
		if ($optinout != 'mandatory') {
			$value = $optstate;
			if (!$this->attribute || !$value) {  // If there is no personal setting for optin, the default is based on the wiki default.
				$value = $this->getConf("optinout") == 'optout';
			}
			$items[] = form_makeCheckboxField('optinout', '1', $this->getLang('twofactor_optin'), '', 'block', $value=='in'?array('checked'=>'checked'):array());
			
		}
		if ($optstate == 'in') {
			// If there is more than one choice, have the user select the default.
			if (count($this->otpMods) > 1) {
				$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;				
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
		//Loop through all modules and render the profile components.
		if ($optstate == 'in') {			
			$parts = array();
			//echo serialize($this->modules).'<hr>';
			foreach ($this->modules as $mod){
				if ($mod->getConf("enable") == 1) {
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
		$form->addElement('<a href="'.wl($ID,array('do'=>'show'),true,'&').'">'.$this->getLang('btn_return').'</a>');
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
		global $USERINFO, $ID, $INFO;
		//msg("Action: ".$event->data);
		// Handle logout.
		if ($event->data == 'logout') {
			$this->_logout();
			return;
		}
		// Handle main login.
		if ($event->data == 'login') {
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
				send_redirect(wl($ID,array('do'=>'login'),true,'&'));
				return;
			}
			// If not logged into twofactor then send there.
			if (!$this->get_clearance()) {
				$event->result = false;
				send_redirect(wl($ID,array('do'=>'twofactor_login'),true,'&'));
				return;
			}
			// Otherwise handle the action.
			$event->result = true;
			return;
		}
		// Check to see if we are heading to the twofactor login.
		if ($event->data == 'twofactor_login') {
			//die( "twofactor_profile in action process handler".$event->data);
			// We will be handling this action's permissions here.
			$event->preventDefault();
			$event->stopPropagation();
			// If not logged into the main auth plugin then send there.
			if (!$USERINFO) {
				$event->result = false;
				send_redirect(wl($ID,array('do'=>'login'),true,'&'));
				return;
			}
			// Otherwise handle the action.
			return;
		}		
		// Handle mandatory authentication.
		if ($this->getConf("optinout") == 'mandatory') {
			// Enforce login.
			if (!$this->get_clearance()) {			
				if (!in_array($event->data, array('login','twofactor_login'))) {
					//msg("Redirect to twofactor login");
					// If not logged in then force to the profile page.
					$event->preventDefault();
					$event->stopPropagation();
					$event->result = false;
					send_redirect(wl($ID,array('do'=>'twofactor_login'),true,'&'));
					return;
				} 
				// Otherwise go to where we are told.
				return;
			}
			// Check to see if updating twofactor is needed.
			$available = count($this->tokenMods) + count($this->otpMods) > 0;
			if (!$available) {
				//die( "mandatory in action process handler".$event->data.serialize($useable));
				// We need to be going to the twofactor profile.
				// If we were, we would not be here in the code.
				$event->preventDefault();
				$event->stopPropagation();
				$event->result = false;
				send_redirect(wl($ID,array('do'=>'twofactor_profile'),true,'&'));
				return;
			}
		}
		//msg(serialize(array($USERINFO, $event->data, $this->getConf("optinout"), $this->get_clearance())));
		// Otherwise everything is good!
		return;
	}
	
	public function twofactor_handle_unknown_action(&$event, $param) {
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
		switch($event->data['type']) {
			case 'twofactor_profile':
				//die(msg(serialize($event)));
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
		if ($this->attribute) {
			$this->attribute->del("twofactor","otp");
		}
		//msg("Logging off.");
		// Before we get here, the session is closed. Reopen it to logout the user.
		if (!headers_sent()) {
			$session = session_status() != PHP_SESSION_NONE;
			if (!$session) { session_start(); }
			//$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = false;
			unset($_SESSION[DOKU_COOKIE]['twofactor_clearance']);
			if (!$session) { session_write_close(); }
			//msg('_logout: '.serialize($_SESSION));
		}
		else {
			msg("Error! You have not been logged off!!!", -1);
		}
		//unset($_SESSION['twofactor_clearance']);
	}

    /**
     * See if the current session has passed two factor authentication.
     * @return bool - true if the session as successfully passed two factor
     *      authentication.
     */
    public function get_clearance() {
		//msg('get_clearance: '.serialize($_SESSION));
		return isset($_SESSION[DOKU_COOKIE]['twofactor_clearance']) && $_SESSION[DOKU_COOKIE]['twofactor_clearance'] === true;
		//return isset($_SESSION['twofactor_clearance'])  && $_SESSION['twofactor_clearance'] === true;
	}

    /**
     * Flags this session as having passed two factor authentication.
     * @return bool - returns true on successfully granting two factor clearance.
     */
    private function _grant_clearance() {
		//msg("Granting clearance.");
		// Purge the otp code as a security measure.
		$this->attribute->del("twofactor","otp");
		if (!headers_sent()) {
			$session = session_status() != PHP_SESSION_NONE;
			if (!$session) { session_start(); }
			$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = true;			
			//msg('_grant_clearance: '.serialize($_SESSION));
			if (!$session) { session_write_close(); }
		}
		else {
			msg("Error! You have not been logged in!!!", -1);
		}
		return $_SESSION[DOKU_COOKIE]['twofactor_clearance']==true;
	}

    /**
     * Handles the authentication check. Screens Google Authenticator OTP, if available.
	 * NOTE: NOT LOGGED IN YET. Attribute requires user name.
     */
    function twofactor_before_auth_check(&$event, $param) {
		global $ACT, $INPUT;
		
		// Only operate if this is a login.
		if ($ACT !== 'login') {	return;	}
		
		// If there is no supplied username, then there is nothing to check at this time.
		if (!$event->data['user']) { return; }
		
		$user = $INPUT->server->str('REMOTE_USER', $event->data['user']);

		// Set helper variables here.
		$this->_setHelperVariables($user);

		// If there is no active user name, then purge our two factor clearance token.
		if ($INPUT->server->str('REMOTE_USER', '') == '') {
			$this->_logout();
		}

		// If the user still has clearance, then we can skip this.		
		if ($this->get_clearance()) { return; }
		
		// Allow the user to try to use login tokens, even if the account cannot use them.
		$otp = $INPUT->str('otp','');
		if ($otp !== '') {  
			// Check for any modules that support OTP at login and are ready for use.
			foreach ($this->tokenMods as $mod){
				$result = $mod->processLogin($otp, $user);
				//msg("Checking login with ".get_class($mod)." result:".serialize($result));
				if ($result) { 
					// The OTP code was valid.
					$this->_grant_clearance();
					return;					
				}
			}
			global $lang;
			msg($lang['badlogin'], -1);
			$event->preventDefault();
			return;
		}

		// No GA OTP was supplied.
		// If the user has no modules available, then grant access.
		// The action preprocessing will send the user to the profile if needed.
		$available = count($this->tokenMods) + count($this->otpMods) > 0;
		if (!$available) {
			//msg("No working modules found.");
			$this->_grant_clearance();
			global $ACT;
			$ACT = 'show';
			//send_redirect(wl($ID,array('do'=>'show'),true,'&'));
			return;
		}		
		
		// At this point, the user has a working module.
		// If the only working module is for a token, then fail.
		if (count($this->otpMods) == 0) {
			die("Must use token.");
			msg($this->getLang('mustusetoken'), -1);
			$event->preventDefault();
			return;
		}
		// The user is logged in to auth, but not into twofactor.  
		// The redirection handler will send the user to the twofactor login.
		//die("Needs two factor");
		return;
    }

    /**
     * @param $event
     * @param $param
     */
    function twofactor_after_auth_check(&$event, $param) {
		global $ACT;

		// Update helper variables here since we are logged in.
		$this->_setHelperVariables();

		if ($ACT == 'twofactor_login') {
			//msg("Processing otp");
			$this->_process_otp($event, $param);
		}
		if ($ACT == 'twofactor_profile') {
			//msg("Processing profile");
			$this->_process_changes($event, $param);
		}
		
	}
	
	
	private function _process_otp(&$event, $param) {	
		global $ACT, $ID, $INPUT;
		
		// See if the user is quitting OTP.  We don't call it logoff because we don't want the user to think they are logged in!
		// This has to be checked before the template is started.
		if ($INPUT->has('otpquit')) {
			// Redirect to logout.
			//send_redirect(wl($ID,array('do'=>'logout'),true,'&'));
			$ACT = 'logout';
			return;
		}

		// Check if the user asked to generate and resend the OTP.
		if ($INPUT->has('resend')) {
			if	($INPUT->has('useall')) {
				$defaultMod = null;
			}
			else {
				$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;
			}
			// At this point, try to send the OTP.
			//msg(serialize($defaultMod));
			$mod = array_key_exists($defaultMod, $this->otpMods) ? $this->otpMods[$defaultMod] : null;
			$this->_send_otp($mod);
			return;
		}

		// If a OTP has been submitted by the user, then verify the OTP.
		// If verified, then grant clearance and continue normally.
		$otp = $INPUT->str('otpcode');
		$user = $INPUT->server->str('REMOTE_USER');
		//msg(serialize(array($otp, $user)));
		if ($otp) {
			foreach ($this->otpMods as $mod){
				$result = $mod->processLogin($otp);
				//msg("Checking login with ".get_class($mod)." result:".serialize($result));
				if ($result) { 
					// The OTP code was valid.
					$this->_grant_clearance();
					//send_redirect(wl($ID,array('do'=>'show'),true,'&'));
					$ACT = 'show';
					return;					
				}
			}
		}
		
	}
	
    /**
     * Process any updates to two factor settings.
     */
    private function _process_changes(&$event, $param) {
		// If the plugin is disabled, then exit.
		//msg("Processing profile.");

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
			$oldoptinout = $this->attribute->get("twofactor","state") === 'in'?'in':'out';
			$optinout = $INPUT->bool('optinout', false)?'in':'out';
			if ($oldoptinout != $optinout) {
				$this->attribute->set("twofactor","state", $optinout);
				$changed = true;
			}
		}

		// Process default module.
		$defaultmodule = $INPUT->str('default_module', '');
		if ($defaultmodule) {
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
		// Update module settings.
		$sendotp = null;
		foreach ($this->modules as $name=>$mod){
			$result = $mod->processProfileForm();
			//msg("$name: ".serialize($result));
			// false:change failed  'failed':OTP failed  null: no change made
			$changed |= $result !== false && $result !== 'failed' && $result !== null;
			switch((string)$result) {
				case 'verified':
					// Remove used OTP.
					$this->attribute->del("twofactor","otp");
					msg($mod->getLang('passedsetup'), 1);
					// The OTP was valid.  Clear the login so the user can continue unbothered.
					$this->_grant_clearance();						
					// Reset helper variables.
					$this->_setHelperVariables();
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
				msg("Could not send message using ".get_class($sendotp),-1);
			}
		}

		// Update change status if changed.
		//msg(serialize($changed));
		if ($changed) {
			msg($this->getLang('updated'), 1);
		}
		return ;
	}

	/**
     * Handles the email and text OTP options.
	 * NOTE: The user will be technically logged in at this point.  This module will rewrite the
	 * page with the prompt for the OTP until validated or the user logs out.
     */
    function twofactor_otp_login(&$event, $param) {
		// Skip this if not logged in or already two factor authenticated.
		//msg(serialize($event));

		// Ensure the OTP exists and is still valid. If we need to, send a OTP.
		$otpQuery = $this->get_otp_code();
		if ($otpQuery == false) {
			$useableMods = array();
			foreach($this->modules as $name=>$mod) {
				if(!$mod->canAuthLogin() && $mod->canUse()) { 
					$useableMods[$mod->getLang("name")] = $mod; 
				}
			}
			$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;
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
     * Transmits a One-Time Password (OTP) configured modules.
     * If $module is set to a specific instance, that instance will be used to 
	 * send the OTP. If not supplied or null, then all configured modules will 
	 * be used to send the OTP. $module can allso be an array of selected 
	 * modules.
     * @return mixed - true if successfull to all attempted tramsmission 
	 *     modules, false if all failed, and a number of how many successes 
	 *     if only some modules failed.
     */
    private function _send_otp($module = null,$force = false) {
		if ($module === null) {			
			$module = $this->otpMods;
		}
		if (!is_array($module)) {
			$modname = get_class($module);
			$module = array($module);
		}		
		if (count($module)==1) {			
			$modname = get_class($module[array_keys($module)[0]]);			
		} 
		else {
			$modname = null;
		}
		
		// Generate the OTP code.
		$characters = '0123456789';
		$otp = '';
		for ($index = 0; $index < $this->getConf('otplength'); ++$index) {
			$otp .= $characters[rand(0, strlen($characters) - 1)];
		}
		// Create the message.
		$message = str_replace('$otp', $otp, $this->getConf('otpcontent'));
		// Pick the delivery method.
		$success = 0;
		foreach($module as $mod) {
			if ($mod->canTransmitMessage()) {
				$success += $mod->transmitMessage($message, $force) ? 1 : 0;
			}
		}
		
		// If partially successful, store the OTP code and the timestamp the OTP expires at.		
		if ($success > 0) {			
			$otpData = array($otp, time() + $this->getConf('sentexpiry') * 60, $modname);
			if (!$this->attribute->set("twofactor","otp", $otpData)){
				msg("Unable to record OTP for later use.", -1);
			}
		}
		return $success == 0 ? false : ($success == count($mod) ? true : $success);
	}
	
	public function get_otp_code() {
		$otpQuery = $this->attribute->get("twofactor","otp", $success);		
		if (!$success) { return false; }
		list($otp, $expiry, $modname) = $otpQuery;
		if (time() > $expiry) {			
			$this->attribute->del("twofactor","otp");
			return false;
		}
		return array($otp, $modname);
	}

	private function _setHelperVariables($user = null) {
		// List all working token modules (GA, RSA, etc.).
		$tokenMods = array();
		foreach($this->modules as $name=>$mod) {
			if($mod->canAuthLogin() && $mod->canUse($user)) { 
				$tokenMods[$mod->getLang("name")] = $mod; 
			}
		}
		$this->tokenMods = $tokenMods;
		//msg("Number of working token modules: ".count($this->tokenMods));
		// List all working OTP modules (SMS, Twilio, etc.).
		$otpMods = array();
		foreach($this->modules as $name=>$mod) {
			if(!$mod->canAuthLogin() && $mod->canUse($user)) { 
				$otpMods[$mod->getLang("name")] = $mod; 
			}
		}
		$this->otpMods = $otpMods;
		//msg("Number of working otp modules: ".count($this->otpMods));
	}	
	
}
