<?php
$meta["enable"] = array('onoff');
$meta["optinout"] = array('multichoice','_choices' => array('optin','optout','mandatory'));
$meta["usega"] = array('onoff');
$meta["gasecret"] = array('string');
$meta["gaexpiry"] = array('numeric');
$meta["useotp"] = array('onoff');
$meta["otpmethod"] = array('multichoice','_choices' => array('email','smsgateway','smsappliance'));
$meta["otpurl"] = array('string');
$meta["otpcontent"] = array('string');
$meta["otplength"] = array('numeric');
$meta["otpexpiry"] = array('numeric');

