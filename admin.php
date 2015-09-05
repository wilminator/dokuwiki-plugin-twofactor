<?php
/*
 *  Twofactor Manager
 *
 *  Dokuwiki Admin Plugin
 *  Special thanks to the useradmin extension as a starting point for this class
 *
 *  @author  Mike Wilmes <mwilmes@avc.edu> 
 */
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

if(!defined('DOKU_TWOFACTOR_PLUGIN_IMAGES')) define('DOKU_TWOFACTOR_PLUGIN_IMAGES',DOKU_BASE.'lib/plugins/twofactor/images/');

/**
 * All DokuWiki plugins to extend the admin function
 * need to inherit from this class
 */
class admin_plugin_twofactor extends DokuWiki_Admin_Plugin {
    protected $_auth = null;        // auth object
    protected $_user_list = array();     // number of users with attributes
    protected $_filter = array();   // user selection filter(s)
    protected $_start = 0;          // index of first user to be displayed
    protected $_last = 0;           // index of the last user to be displayed
    protected $_pagesize = 20;      // number of users to list on one page
    protected $_disabled = '';      // if disabled set to explanatory string
    protected $_lastdisabled = false; // set to true if last user is unknown and last button is hence buggy

    /**
     * Constructor
     */
    public function __construct(){
		global $auth;
        if (!isset($auth)) {
            $this->_disabled = $this->lang['noauth'];
        } else if (!$auth->canDo('getUsers')) {
            $this->_disabled = $this->lang['nosupport'];
        } else {
            // we're good to go
            $this->_auth = & $auth;
        }
		$this->setupLocale();
		$requireAttribute = $this->getConf("enable") === 1 && 
			($this->getConf("usega") === 1 || 
			($this->getConf("useotp") === 1 && ($this->getConf("otpmethod") != 'email' || $this->getConf("optinout") != 'mandatory')));
		$this->attribute = $requireAttribute ? $this->loadHelper('attribute', 'Attribute plugin required!') : null;		
		$this->_getUsers();
    }
	
	protected function _getUsers() {
		if (!is_null($this->attribute)) {
			$attr = $this->attribute;
			$this->_user_list = $this->attribute->enumerateUsers('twofactor');
		}
		else {
			msg($this->lang['no_purpose'], -1);
		}
	}
	
    /**
     * Return prompt for admin menu
     *
     * @param string $language
     * @return string
     */
    public function getMenuText($language) {
		global $INFO;
        if (!$INFO['isadmin'])
          return parent::getMenuText($language);

        return $this->getLang('menu').' '.$this->_disabled;
    }

    /**
     * return sort order for position in admin menu
     *
     * @return int
     */
    public function getMenuSort() {
        return 2;
    }

    /**
     * @return int current start value for pageination
     */
    public function getStart() {
        return $this->_start;
    }

    /**
     * @return int number of users per page
     */
    public function getPagesize() {
        return $this->_pagesize;
    }

    /**
     * @param boolean $lastdisabled
     */
    public function setLastdisabled($lastdisabled) {
        $this->_lastdisabled = $lastdisabled;
    }

    /**
     * Handle user request
     *
     * @return bool
     */
    public function handle() {
        global $INPUT, $INFO;
        if (!$INFO['isadmin']) return false;

        // extract the command and any specific parameters
        // submit button name is of the form - fn[cmd][param(s)]
        $fn   = $INPUT->param('fn');

        if (is_array($fn)) {
            $cmd = key($fn);
            $param = is_array($fn[$cmd]) ? key($fn[$cmd]) : null;
        } else {
            $cmd = $fn;
            $param = null;
        }

        if ($cmd != "search") {
            $this->_start = $INPUT->int('start', 0);
            $this->_filter = $this->_retrieveFilter();
        }

        switch($cmd){
            case "reset"  : $this->_resetUser(); break;
            case "search" : $this->_setFilter($param);
                            $this->_start = 0;
                            break;
        }

        $this->_user_total = count($this->_user_list) > 0 ? $this->_getUserCount($this->_filter) : -1;

        // page handling
        switch($cmd){
            case 'start' : $this->_start = 0; break;
            case 'prev'  : $this->_start -= $this->_pagesize; break;
            case 'next'  : $this->_start += $this->_pagesize; break;
            case 'last'  : $this->_start = $this->_user_total; break;
        }
        $this->_validatePagination();
        return true;
    }

    /**
     * Output appropriate html
     *
     * @return bool
     */
    public function html() {
        global $ID, $INFO;

        if(!$INFO['isadmin']) {
            print $this->lang['badauth'];
            return false;
        }

        $user_list = $this->_retrieveUsers($this->_start, $this->_pagesize, $this->_filter);

        $page_buttons = $this->_pagination();

        print $this->locale_xhtml('intro');
        print $this->locale_xhtml('list');

        ptln("<div id=\"user__manager\">");
        ptln("<div class=\"level2\">");

        if (count($this->_user_list) > 0) {
            ptln("<p>".sprintf($this->lang['summary'],$this->_start+1,$this->_last,$this->_getUserCount($this->_filter),count($this->_user_list))."</p>");
        } else {
            if(count($this->_user_list) < 0) {
                $allUserTotal = 0;
            } else {
                $allUserTotal = count($this->_user_list);
            }
            ptln("<p>".sprintf($this->lang['nonefound'], $allUserTotal)."</p>");
        }
        ptln("<form action=\"".wl($ID)."\" method=\"post\">");
        formSecurityToken();
        ptln("  <div class=\"table\">");
        ptln("  <table class=\"inline\">");
        ptln("    <thead>");
        ptln("      <tr>");
        ptln("        <th>&#160;</th><th>".$this->lang["user_id"]."</th><th>".$this->lang["user_name"]."</th><th>".$this->lang["user_mail"]."</th>");
        ptln("      </tr>");

        ptln("      <tr>");
        ptln("        <td class=\"rightalign\"><input type=\"image\" src=\"".DOKU_TWOFACTOR_PLUGIN_IMAGES."search.png\" name=\"fn[search][new]\" title=\"".$this->lang['search_prompt']."\" alt=\"".$this->lang['search']."\" class=\"button\" /></td>");
        ptln("        <td><input type=\"text\" name=\"userid\" class=\"edit\" value=\"".$this->_htmlFilter('user')."\" /></td>");
        ptln("        <td><input type=\"text\" name=\"username\" class=\"edit\" value=\"".$this->_htmlFilter('name')."\" /></td>");
        ptln("        <td><input type=\"text\" name=\"usermail\" class=\"edit\" value=\"".$this->_htmlFilter('mail')."\" /></td>");
        ptln("      </tr>");
        ptln("    </thead>");

        if ($this->_user_total) {
            ptln("    <tbody>");
            foreach ($user_list as $user => $userinfo) {
                extract($userinfo);
                /**
                 * @var string $name
                 * @var string $pass
                 * @var string $mail
                 * @var array  $grps
                 */
                $groups = join(', ',$grps);
                ptln("    <tr class=\"user_info\">");
                ptln("      <td class=\"centeralign\"><input type=\"checkbox\" name=\"delete[".hsc($user)."]\" ".$delete_disable." /></td>");
                if ($editable) {
                    ptln("    <td><a href=\"".wl($ID,array('fn[edit]['.$user.']' => 1,
                                                           'do' => 'admin',
                                                           'page' => 'usermanager',
                                                           'sectok' => getSecurityToken())).
                         "\" title=\"".$this->lang['edit_prompt']."\">".hsc($user)."</a></td>");
                } else {
                    ptln("    <td>".hsc($user)."</td>");
                }
                ptln("      <td>".hsc($name)."</td><td>".hsc($mail)."</td>");
                ptln("    </tr>");
            }
            ptln("    </tbody>");
        }

        ptln("    <tbody>");
        ptln("      <tr><td colspan=\"5\" class=\"centeralign\">");
        ptln("        <span class=\"medialeft\">");
        ptln("          <button type=\"submit\" name=\"fn[reset]\" id=\"usrmgr__reset\" >".$this->lang['reset_selected']."</button>");
        ptln("        ");
        if (!empty($this->_filter)) {
            ptln("    <button type=\"submit\" name=\"fn[search][clear]\">".$this->lang['clear']."</button>");
        }
        ptln("        <input type=\"hidden\" name=\"do\"    value=\"admin\" />");
        ptln("        <input type=\"hidden\" name=\"page\"  value=\"twofactor\" />");

        $this->_htmlFilterSettings(2);
        ptln("        </span>");
        ptln("        <span class=\"mediaright\">");
        ptln("          <button type=\"submit\" name=\"fn[start]\" ".$page_buttons['start'].">".$this->lang['start']."</button>");
        ptln("          <button type=\"submit\" name=\"fn[prev]\" ".$page_buttons['prev'].">".$this->lang['prev']."</button>");
        ptln("          <button type=\"submit\" name=\"fn[next]\" ".$page_buttons['next'].">".$this->lang['next']."</button>");
        ptln("          <button type=\"submit\" name=\"fn[last]\" ".$page_buttons['last'].">".$this->lang['last']."</button>");
        ptln("        </span>");

        ptln("      </td></tr>");
        ptln("    </tbody>");
        ptln("  </table>");
        ptln("  </div>");

        ptln("</form>");
        ptln("</div>");

        ptln("</div>");
        return true;
    }


    /**
     * Prints a inputfield
     *
     * @param string $id
     * @param string $name
     * @param string $label
     * @param string $value
     * @param bool   $cando whether auth backend is capable to do this action
     * @param int $indent
     */
    protected function _htmlInputField($id, $name, $label, $value, $cando, $indent=0) {
        $class = $cando ? '' : ' class="disabled"';
        echo str_pad('',$indent);

        if($name == 'userpass' || $name == 'userpass2'){
            $fieldtype = 'password';
            $autocomp  = 'autocomplete="off"';
        }elseif($name == 'usermail'){
            $fieldtype = 'email';
            $autocomp  = '';
        }else{
            $fieldtype = 'text';
            $autocomp  = '';
        }
        $value = hsc($value);

        echo "<tr $class>";
        echo "<td><label for=\"$id\" >$label: </label></td>";
        echo "<td>";
        if($cando){
            echo "<input type=\"$fieldtype\" id=\"$id\" name=\"$name\" value=\"$value\" class=\"edit\" $autocomp />";
        }else{
            echo "<input type=\"hidden\" name=\"$name\" value=\"$value\" />";
            echo "<input type=\"$fieldtype\" id=\"$id\" name=\"$name\" value=\"$value\" class=\"edit disabled\" disabled=\"disabled\" />";
        }
        echo "</td>";
        echo "</tr>";
    }

    /**
     * Returns htmlescaped filter value
     *
     * @param string $key name of search field
     * @return string html escaped value
     */
    protected function _htmlFilter($key) {
        if (empty($this->_filter)) return '';
        return (isset($this->_filter[$key]) ? hsc($this->_filter[$key]) : '');
    }

    /**
     * Print hidden inputs with the current filter values
     *
     * @param int $indent
     */
    protected function _htmlFilterSettings($indent=0) {

        ptln("<input type=\"hidden\" name=\"start\" value=\"".$this->_start."\" />",$indent);

        foreach ($this->_filter as $key => $filter) {
            ptln("<input type=\"hidden\" name=\"filter[".$key."]\" value=\"".hsc($filter)."\" />",$indent);
        }
    }

    /**
     * Reset user (a user has been selected to remove two factor authentication)
     *
     * @param string $param id of the user
     * @return bool whether succesful
     */
    protected function _resetUser() {
        global $INPUT;
		if (!checkSecurityToken()) return false;

        $selected = $INPUT->arr('delete');
        if (empty($selected)) return false;
        $selected = array_keys($selected);

        if(in_array($_SERVER['REMOTE_USER'], $selected)) {
            msg($this->lang['reset_not_self'], -1);
            return false;
        }
		
		$count = 0;
		foreach($selected as $user) {
			// All users here have a attribute namespace file. Purge them.
			$count += $this->attribute->purge('twofactor', $user)? 1 : 0;
		}

        if ($count == count($selected)) {
            $text = str_replace('%d', $count, $this->lang['reset_ok']);
            msg("$text.", 1);
        } else {
            $part1 = str_replace('%d', $count, $this->lang['reset_ok']);
            $part2 = str_replace('%d', (count($selected)-$count), $this->lang['reset_fail']);
            msg("$part1, $part2",-1);
        }
		
		// Now refresh the user list.
		$this->_getUsers();
		
        return true;
    }
	
	protected function _retrieveFilteredUsers($filter = array()) {
		$users = array();
		foreach ($this->_user_list as $user) {
			$userdata = $this->_auth->getUserData($user);
			$include = true;
			foreach ($filter as $key=>$value) {
				$include &= strstr($userdata[$key], $value);
			}
			if ($include) { $users[$user] = $userdata; }
		}
		return $users;
	}
	
	protected function _getUserCount($filter) {
		return count($this->_retrieveFilteredUsers($filter));
	}

	protected function _retrieveUsers($start, $pagesize, $filter) {
		$users = $this->_retrieveFilteredUsers($filter);
		return $users;
	}

    /**
     * Retrieve & clean user data from the form
     *
     * @param bool $clean whether the cleanUser method of the authentication backend is applied
     * @return array (user, password, full name, email, array(groups))
     */
    protected function _retrieveUser($clean=true) {
        /** @var DokuWiki_Auth_Plugin $auth */
        global $auth;
        global $INPUT;

        $user = array();
        $user[0] = ($clean) ? $auth->cleanUser($INPUT->str('userid')) : $INPUT->str('userid');
        $user[1] = $INPUT->str('userpass');
        $user[2] = $INPUT->str('username');
        $user[3] = $INPUT->str('usermail');
        $user[4] = explode(',',$INPUT->str('usergroups'));
        $user[5] = $INPUT->str('userpass2');                // repeated password for confirmation

        $user[4] = array_map('trim',$user[4]);
        if($clean) $user[4] = array_map(array($auth,'cleanGroup'),$user[4]);
        $user[4] = array_filter($user[4]);
        $user[4] = array_unique($user[4]);
        if(!count($user[4])) $user[4] = null;

        return $user;
    }

    /**
     * Set the filter with the current search terms or clear the filter
     *
     * @param string $op 'new' or 'clear'
     */
    protected function _setFilter($op) {

        $this->_filter = array();

        if ($op == 'new') {
            list($user,/* $pass */,$name,$mail,$grps) = $this->_retrieveUser(false);

            if (!empty($user)) $this->_filter['user'] = $user;
            if (!empty($name)) $this->_filter['name'] = $name;
            if (!empty($mail)) $this->_filter['mail'] = $mail;
        }
    }

    /**
     * Get the current search terms
     *
     * @return array
     */
    protected function _retrieveFilter() {
        global $INPUT;

        $t_filter = $INPUT->arr('filter');

        // messy, but this way we ensure we aren't getting any additional crap from malicious users
        $filter = array();

        if (isset($t_filter['user'])) $filter['user'] = $t_filter['user'];
        if (isset($t_filter['name'])) $filter['name'] = $t_filter['name'];
        if (isset($t_filter['mail'])) $filter['mail'] = $t_filter['mail'];

        return $filter;
    }

    /**
     * Validate and improve the pagination values
     */
    protected function _validatePagination() {

        if ($this->_start >= $this->_user_total) {
            $this->_start = $this->_user_total - $this->_pagesize;
        }
        if ($this->_start < 0) $this->_start = 0;

        $this->_last = min($this->_user_total, $this->_start + $this->_pagesize);
    }

    /**
     * Return an array of strings to enable/disable pagination buttons
     *
     * @return array with enable/disable attributes
     */
    protected function _pagination() {

        $disabled = 'disabled="disabled"';

        $buttons = array();
        $buttons['start'] = $buttons['prev'] = ($this->_start == 0) ? $disabled : '';

        if ($this->_user_total == -1) {
            $buttons['last'] = $disabled;
            $buttons['next'] = '';
        } else {
            $buttons['last'] = $buttons['next'] = (($this->_start + $this->_pagesize) >= $this->_user_total) ? $disabled : '';
        }

        if ($this->_lastdisabled) {
            $buttons['last'] = $disabled;
        }

        return $buttons;
    }

	
}
