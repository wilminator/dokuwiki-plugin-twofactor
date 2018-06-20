<?php

namespace dokuwiki\Menu\Item;

/**
 * Class Profile2FA
 *
 * Open the user's 2FA profile
 */
class Profile2FA extends Profile {

    /** @inheritdoc */
    public function __construct() {
        global $INPUT;
        parent::__construct();

        // Borrow the Profile  language construct.
        global $lang;        
        $this->label = $lang['btn_profile'].' (2FA)';        
    }

    public function getType() {
        if($this->type === '') {
            $this->type = 'twofactor_profile';
        }
        return $this->type;
    }
}
