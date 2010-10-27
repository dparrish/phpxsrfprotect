<?php

include "XsrfProtection.php";

// Create the protection object
$prot = new XsrfProtection();
// Set a secret key. This should really be secret, but must be shared between
// all your frontends that will be handling this type of request.
$prot->SetKey("CHANGE_THIS_KEY_TO_SOMETHING_ONLY_YOU_KNOW");
// Set some user data. This would normally be the logged in user or some other
// identifying field.
$prot->SetUserData("dparrish");
// Set the URL field
$prot->SetUrl("http://www.test.com/xsrf/example.php");
// Set the maximum age of tokens. The default is 1 hour.
$prot->SetTimeout(3600);
// Use the session cache to prevent replay attacks.
session_start();
$prot->SetStateful();


if (isset($_REQUEST['test'])) {
  // Validate the submitted form token.
  $ret = $prot->Validate($_POST);
  if ($ret != XsrfProtection::kCheckSuccess) {
    // There was an error, print out the reason. This is not a good idea in
    // production, but works for an example.
    print "XSRF detected, validation failure ". $prot->Error(). "\n";
    return;
  }
  // All good, print something out and return
  print "Test value: ". $_REQUEST['test'];
  return;
}

// Generate a very basic form that has XSRF protection.
?>
<form method='post'>
<input type='text' name='test' value='foobar'>
<input type='submit' name='doit' value='Submit'>
<?=$prot->ProtectionField()?>
</form>
