<?php
abstract class Twofactor_Auth_Module extends DokuWiki_Plugin {
	protected $twofactor = null;
	
	/**
	 * As a requirement, this class and its subclasses require the attribute
	 * plugin for access to user data. An array will be passed in that the 
	 * calling class will handle saving data changes.  As such, the calling 
	 * class will ensure that the correct user's settings are presented to 
	 * this module.
	 */
	public function __construct(){
        $this->loadConfig();		
		$this->attribute = plugin_load('helper', 'attribute');
        $this->success = $this->attribute != null && strstr(get_called_class(), 'helper_plugin_');				
		$this->moduleName = substr(get_called_class(), strlen('helper_plugin_'));
	}
	
    /**
     * return some info
     */
    public function getInfo() {
        return array(
            'author' => 'Mike Wilmes',
            'email'  => 'mwilmes@avc.edu',
            'date'   => '2015-09-03',
            'name'   => 'Twofactor Auth Plugin',
            'desc'   => 'Template object used to create Twofactor Authentication modules.',
            'url'    => 'http://www.dokuwiki.org/plugin:twofactor',
        );
    }

    /**
     * Return info about supported methods in this Helper Plugin
     *
     * @return array of public methods
     */
    public function getMethods() {
        $result   = array();
        $result[] = array(
            'name'       => 'canUse',
            'desc'       => "This is called to see if the user can use it to login.",
            'parameters' => array(                
                'user' => 'string',
            ),
            'return'     => array('useable' => 'boolean'),
        );
        $result[] = array(
            'name'       => 'canAuthLogin',
            'desc'       => "This is called to see if the module provides login functionality on the main login page.",
            'parameters' => array(
            ),
            'return'     => array('OTP_at_login' => 'boolean'), 
        );
        $result[] = array(
            'name'       => 'renderProfileForm',
            'desc'       => "This is called to render the user configurable portion of the module inside the user's profile.  Default is to render nothing.",
            'parameters' => array(
            ),
            'return'     => array('html_elements' => 'array'),
        );
        $result[] = array(
            'name'       => 'processProfileForm',
            'desc'       => "This is called to process the user configurable portion of the module inside the user's profile.",
            'parameters' => array(
            ),
            'return'     => array('results' => 'mixed'),
        );
        $result[] = array(
            'name'       => 'canTransmitMessage',
            'desc'       => "This is called to see if the module can send a message to the user.",
            'parameters' => array(
            ),
            'return'     => array('useable' => 'boolean'),
        );
        $result[] = array(
            'name'       => 'transmitMessage',
            'desc'       => "This is called to relay a message to the user.  The message should usually have a code for the user, but might be used to send a notice that someone has logged in using their account.",
            'parameters' => array(
                'message' => 'string',
            ),
            'return'     => array('success' => 'boolean'), // returns false on error.
        );
        $result[] = array(
            'name'       => 'processLogin',
            'desc'       => "This is called to validate the code provided.  The default is to see if the code matches the one-time password.",
            'parameters' => array(
                'code' => 'string',
                'user' => 'string',
            ),
            'return'     => array('success' => 'boolean'),
        );
        return $result;
    }

	/**
	 * This is called to see if the user can use it to login.
	 * @return bool - True if this module has access to all needed information 
	 * to perform a login.
	 */
    abstract public function canUse($user = null);
	
	/**
	 * This is called to see if the module provides login functionality on the 
	 * main login page.
	 * @return bool - True if this module provides main login functionality.
	 */
    abstract public function canAuthLogin();

	/**
	 * This is called to render the user configurable portion of the module 
	 * inside the user's profile.  Default is to render nothing.
	 * NOTE: Use string indexes for fields that can be consolidated, eg phone 
	 *       numbers.
	 * @return array - Array of HTML form elements to insert into the profile 
	 *     page.
	 */
    public function renderProfileForm() { return array(); }
    
	/**
	 * This is called to process the user configurable portion of the module 
	 * inside the user's profile.
	 * @return mixed - True if the user's settings were changed, false if 
	 *     settings could not be changed, null if no settings were changed, 
	 *     the string 'verified' if the module was successfully verified,
	 *     the string 'failed' if the module failed verification,
	 *	   the string 'otp' if the module is requesting a one-time password
	 *     for verification.
	 */
    public function processProfileForm() { return null; }    
    
	/**
	 * This is called to see if the module can send a message to the user.
	 * @return bool - True if a message can be sent to the user.
	 */
	abstract public function canTransmitMessage();

	/**
	 * This is called to relay a message to the user.  The message should 
	 * usually have a code for the user, but might be used to send a notice 
	 * that someone has logged in using their account.
	 * @return bool - True if the message was sucecssfully transmitted.
	 */
	public function transmitMessage($message, $force = false) { return false; }

	/**
	 * This is called to validate the code provided.  The default is to see if 
	 * the code matches the one-time password.
	 * @return bool - True if the user has successfully authenticated using 
	 * this mechanism.
	 */
	public function processLogin($code, $user = null) {
		$twofactor = plugin_load('action', 'twofactor');
		$otpQuery = $twofactor->get_otp_code();
		//msg(serialize(array($otpQuery,$code, $user)));
		if (!$otpQuery) { return false; }
		list($otp, $modname) = $otpQuery;
		return ($code == $otp && $code != '' && ($modname == null || $modname == get_called_class()));
	}
	
	/**
	 * This is a helper function to get text strings from the twofactor class 
	 * calling this module.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _getSharedLang($key) {	
		$twofactor = plugin_load('action', 'twofactor');	
		return $twofactor->getLang($key);
	}
	
	/**
	 * This is a helper function to get shared configuration options from the 
	 * twofactor class.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _getSharedConfig($key) {	
		$twofactor = plugin_load('action', 'twofactor');	
		return $twofactor->getConf($key);
	}
	
	/**
	 * This is a helper function to check for the existence of shared 
	 * twofactor settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _sharedSettingExists($key) {		
		return $this->attribute->exists("twofactor", $key);
	}
	
	/**
	 * This is a helper function to get shared twofactor settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _sharedSettingGet($key, $default = null, $user = null) {		
		return $this->_sharedSettingExists($key) ? $this->attribute->get("twofactor", $key, $success, $user) : $default;
	}

	/**
	 * This is a helper function to set shared twofactor settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _sharedSettingSet($key, $value) {		
		return $this->attribute->set("twofactor", $key, $value);
	}
	
	/**
	 * This is a helper function to check for the existence of module 
	 * specific settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _settingExists($key, $user = null) {		
		return $this->attribute->exists($this->moduleName, $key, $user);
	}
	
	/**
	 * This is a helper function to get module specific settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _settingGet($key, $default = null, $user = null) {		
		return $this->_settingExists($key, $user) ? $this->attribute->get($this->moduleName, $key, $success, $user) : $default;
	}

	/**
	 * This is a helper function to set module specific settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _settingSet($key, $value) {		
		return $this->attribute->set($this->moduleName, $key, $value);
	}

	/**
	 * This is a helper function to delete module specific settings.	 
	 * @return string - Language string from the calling class.
	 */
	protected function _settingDelete($key) {		
		return $this->attribute->del($this->moduleName, $key);
	}

	/**
	 * This is a helper function that lists the names of all available 
	 * modules. 	 
	 * @return array - Names of availble modules.
	 */
	static public function _listModules(){
		$modules = plugin_list();		
		return array_filter($modules, function($x){ return substr($x, 0, 9)==='twofactor' && $x !== 'twofactor';});
	}

	/**
	 * This is a helper function that attempts to load the named modules.
	 * @return array - An array of instanced objects from the loaded modules.
	 */
	static public function _loadModules($mods){
		$objects = array();
		foreach ($mods as $mod) {	
			$obj = plugin_load('helper', $mod);
			if ($obj && is_a($obj, 'Twofactor_Auth_Module')) {
				$objects[$mod] = $obj;
			}
		}
		return $objects;
	}
}