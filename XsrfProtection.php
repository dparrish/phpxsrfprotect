<?php
/**
 * Simple XSRF Protection
 *
 * @version 1.0
 * @copyright Copyright (c) 2010, David Parrish
 * @author David Parrish <david@dparrish.com>
 * @package XsrfProtection
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 *
 */

/**
 * Simple XSRF Protection
 *
 * This class provides a simple method of protecting form submission from
 * common Cross Site Request Forgery (XSRF) attacks.
 *
 * Protection is accomplished by adding a randomised hidden field to forms that
 * are checked when the form is processed. If the hidden field doesn't exist,
 * or is modified then the request should be rejected.
 *
 * The method used is stateless and does not require any session management to
 * be used. This allows the request to be easily handled by a load balanced
 * cluster of frontends that don't share session information.
 *
 * Protection against replay attacks can also be provided using this same
 * method, but requiring session local storage which makes this stateful, and
 * requires distributed session management if multiple web servers are being
 * used.
 *
 * @example example.php Sample usage
 *
 */

class XsrfProtection {

  /**
   * Validation successful, this is likely not a forged request.
   */
  const kCheckSuccess = 0;
  /**
   * Validation failed, the security token was invalid.
   */
  const kCheckInvalid = 1;
  /**
   * Validation failed, the security token has expired.
   */
  const kCheckExpired = 2;
  /**
   * Validation failed, the security token was missing.
   */
  const kCheckMissing = 3;
  /**
   * Validation failed, the security token had already been used.
   */
  const kCheckReused = 4;

  /**
   * Sets the hash secret key.
   *
   * This is required for the protection to work. If you don't set this key,
   * you will get a PHP error in the log.
   *
   * DO NOT use the example key, as it is the only protection provided by this
   * class. If you use the example key, forging requests becomes trivial.
   *
   * @param string $key The new hash secret key
   */
  function SetKey($key) {
    $this->_key = $key;
  }

  /**
   * Sets the user data.
   *
   * Use user data to provide an extra level of security. The data will be used
   * as part of the security token, so must be reproducable when verifying the
   * token.
   *
   * It's recommended that a username or user ID is used for this field.
   *
   * @param string $data New user data
   */
  function SetUserData($data) {
    $this->_user_data = $data;
  }

  /**
   * Sets the target URL.
   *
   * This provides an extra level of security by adding another checked field
   * into the security token. This is not checked against the actual URL of the
   * script, so it's up to the author to ensure it's something useful.
   *
   * @param string $url New target URL
   */
  function SetUrl($url) {
    $this->_url = $url;
  }

  /**
   * Enable stateful mode.
   *
   * Stateful mode adds an extra level of security, only allowing tokens to be
   * used a single time. This prevents replay attacks, but requires use of the
   * PHP session cache.
   *
   * Be sure you call session_start() beforre trying to use the stateful
   * mode.
   *
   * @see session_start()
   * @param bool $stateful Whether stateful mode should be enabled.
   */
  function SetStateful($stateful = true) {
    $this->_stateful = $stateful;
  }

  /**
   * Set the maximum age of tokens.
   * If a request is received with a token that is older than this, it is
   * rejected.
   *
   * @param int $age The maximum age of tokens in seconds. This defaults to 1
   * hour if not specified.
   */
  function SetTimeout($age) {
    $this->_max_age = $age;
  }

  /**
   * Sert a custom token field name. By default this is __xsrfprotect_tok. If
   * that doesn't fit in with your field naming scheme, you can choose another
   * one with this method.
   *
   * @param string $field The new field name. This must not be used for any other purpose.
   */
  function SetFieldName($field) {
    $this->_field_name = $field;
  }

  /**
   * Get the value that would be set in the hidden field.
   *
   * You could for example use this in a GET request.
   *
   * @return string The token value
   */
  function ProtectionFieldValue() {
    if (!$this->_key) {
      trigger_error("XsrfProtection failure: No secret key has been set",
        E_USER_ERROR);
      return null;
    }

    return base64_encode(hash_hmac("sha256", $this->_ProtectionData(time()),
      $this->_key). ":". time());
  }

  /**
   * Return the hidden input field that contains the secret token.
   *
   * This is the only method you are required to call when generating the form.
   *
   * @return string The complete <input> tag suitable for printing.
   */
  function ProtectionField() {
    if (!$this->_key) {
      trigger_error("XsrfProtection failure: No secret key has been set",
        E_USER_ERROR);
      return null;
    }

    $fields = "<input type='hidden' name='". $this->_field_name. "' value='".
      $this->ProtectionFieldValue(). "'>";
    return $fields;
  }

  /**
   * Validates the supplied token.
   *
   * This is the only method you are required to call when validating the
   * token. It performas all the checks of the token. You can pass in an array
   * of request variables, and it's recommended that you either pass in $_GET
   * or $_POST, depending on how you expect your form to be received.
   *
   * This will return one of the kCheck* constants which can be used to see why
   * the request was rejected. A return value of 0 indicates success (a valid
   * request).
   *
   * @param array $req The request fields, defaults to $_REQUEST
   * @return int Success or failure of the validation. 0 is success.
   */
  function Validate($req = null) {
    if (!$this->_key) {
      $this->_error = "No secret key has been set";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_ERROR);
      return self::kCheckInvalid;
    }

    if ($req === null)
      $req = $_REQUEST;

    if (!is_array($req)) {
      $this->_error = "Missing request array";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
      return self::kCheckMissing;
    }

    if (!isset($req[$this->_field_name])) {
      $this->_error = "Missing token";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
      return self::kCheckMissing;
    }

    $decdata = base64_decode($req[$this->_field_name]);
    $parts = explode(":", $decdata, 2);
    if (!$parts || count($parts) != 2) {
      $this->_error = "Broken token data";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
      return self::kCheckInvalid;
    }

    $teststr = hash_hmac("sha256", $this->_ProtectionData($parts[1]),
      $this->_key);

    if ($teststr != $parts[0]) {
      $this->_error = "Invalid token";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
      return self::kCheckInvalid;
    }

    if ($parts[1] < time() - $this->_max_age) {
      $this->_error = "Token has expired";
      trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
      return self::kCheckExpired;
    }

    if ($this->_stateful) {
      if (!isset($_SESSION['__xsrfprotection_used_keys']))
        $_SESSION['__xsrfprotection_used_keys'] = array();
      if (isset($_SESSION['__xsrfprotection_used_keys'][$teststr])) {
        $this->_error = "Token has already been used";
        trigger_error("XsrfProtection failure: $this->_error", E_USER_WARNING);
        return self::kCheckReused;
      }
      $_SESSION['__xsrfprotection_used_keys'][$teststr] = true;
    }

    return self::kCheckSuccess;
  }

  /**
   * Get a human-readable explanation of why the request was rejected.
   *
   * This is suitable for printing, but it's recommended that it's not shown to
   * users, as it may help an attacker devise a better attack.
   *
   * @return string The error message for the last validation.
   */
  function Error() {
    return $this->_error;
  }

  /**
   *
   * @access private
   */
  private function _ProtectionData($time) {
    return implode(":", array($time, $this->_url, $this->_user_data));
  }

  private $_key = null;
  private $_field_name = "__xsrfprotect_tok";
  private $_url = null;
  private $_user_data = null;
  private $_max_age = 3600;
  private $_stateful = false;
  private $_error = null;

}

?>
