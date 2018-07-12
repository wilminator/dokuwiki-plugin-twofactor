<?php
$meta["enable"] = array('onoff');
$meta["optinout"] = array('multichoice','_choices' => array('optin','optout','mandatory'));
$meta["otpsubject"] = array('string');
$meta["otpcontent"] = array('string');
$meta["generatorexpiry"] = array('numeric');
$meta["otplength"] = array('numeric');
$meta["sentexpiry"] = array('numeric');
$meta["loginnotice"] = array('multichoice','_choices' => array('none','user','always'));
$meta["loginsubject"] = array('string');
$meta["logincontent"] = array('string');
$meta["refreshexpiry"] = array('numeric');
$meta["logging_level"] = array('multichoice','_choices' => array('0','1','2','3','4'));
$meta["logging_path"] = array('string');
