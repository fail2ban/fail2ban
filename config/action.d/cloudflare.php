<?php
  /**
  *---------------------------------------------------------------
  * Cloudflare API script
  *---------------------------------------------------------------
  *
  * aim to extend Fail2Ban ability with more complexity support
  * for cloudflare list.
  *
  * @author: Robert Kuntz
  * @version: 1.0
  * @requirements php-cli
  *
  * @param array @argv given script argument
  * @return int exit code
  **/

  /**
  * Need token permissions:
  *
  * All accounts - Account Filter Lists:Edit, Account Settings:Read
  * All zones - Zone:Read, Firewall Services:Edit
  **/

  /**
  * PLANED FEATURES
  *
  * add optional predefined list to fw rule
  * multi zone support
  * workaround for permission test (token access require to much token power security wise)
  * adding ipv6 support
  * adding bulk opperation support
  **/

  /**
  * CONFIG
  **/
  $config_file_path = "/etc/fail2ban/";
  $cloudflare_api_url = "https://api.cloudflare.com/client/v4/";
  $tmp_dir = "/tmp/";

  /**
  * INIT
  **/
  $log_file = get_option("fail2ban", "logtarget");
  $pid_file = get_option("fail2ban", "pidfile");
  $cloudflare_token = get_option("jail", "cftoken");
  $cloudflare_account = get_option("jail", "cfaccount");
  $cloudflare_zone = get_option("jail", "cfzone");
  $process_id = get_pid();
  $list_id = get_lid();

  // parse argv
  $action = $argv[1];
  if($argc == 3) $target = $argv[2];

  /**
  * script actions
  **/
  if($action == "start") {
    log_msg("", 1);
    log_msg("====================", 1);
    log_msg("Cloudlfare API start", 1);
    log_msg("====================", 1);
    log_msg("Cloudlfare cleanup and init process for list, filter rule and firewall rule.", 1);
    log_msg("", 1);

    // run cleanup process
    cf_cleanup();

    // create new list
    $data = array();
    $data['name'] = 'fail2ban';
    $data['kind'] = 'ip';
    $data['description'] = 'Fail2Ban automatic ban list';

    log_msg("Creating new fail2ban list.", 1);
    $res = api_request('accounts/'.$cloudflare_account.'/rules/lists', 'POST', $data);

    if($res["success"] == true) {
      log_msg("Fail2ban list successfull created.", 1);

      // store list id
      if(save_lid($res["result"]["id"]) == false) {
        log_msg("Could not store list id.", 4);
      }
      else {
        log_msg("List id stored.", 1);
      }
    }
    else {
      log_msg("Could not create fail2ban list.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 2);

    // create new filter rule
    $data = array();
    $data['expression'] = '(ip.src in $fail2ban)';
    $data['paused'] = false;
    $data['description'] = 'fail2ban';
    $data['ref'] = 'fail2ban';

    log_msg("Create new filter rule", 1);
    $res = api_request('zones/'.$cloudflare_zone.'/filters', 'POST', $data, true);

    if($res["success"] == true) {
      log_msg("Fail2ban filter successfull created.", 1);
      $filter_id = $res["result"][0]["id"];
      $filter_ref = $res["result"][0]["ref"];
    }
    else {
      log_msg("Could not create fail2ban filter.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);

    // create new firewall rule
    $data = array();
    $data['action'] = 'block';
    $data['filter']['id'] = $filter_id;
    $data['filter']['expression'] = '(ip.src in $fail2ban)';
    $data['filter']['paused'] = false;
    $data['filter']['description'] = 'fail2ban';
    $data['filter']['ref'] = $filter_ref;

    log_msg("Create new firewall rule", 1);
    $res = api_request('zones/'.$cloudflare_zone.'/firewall/rules', 'POST', $data, true);

    if($res["success"] == true) {
      log_msg("Fail2ban firewall successfull created.", 1);
    }
    else {
      log_msg("Could not create fail2ban firewall.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);
    log_msg("Init finish", 2);
    log_msg("", 1);
  }
  elseif($action == "stop") {
    log_msg("", 1);
    log_msg("===================", 1);
    log_msg("Cloudlfare API stop", 1);
    log_msg("===================", 1);
    log_msg("Cloudlfare cleanup process for list, filter rule and firewall rule.", 1);
    log_msg("", 1);

    // run cleanup process
    cf_cleanup();
  }
  elseif($action == "ban") {
    $data = array();
    $data['ip'] = $target;

    $res = api_request('accounts/'.$cloudflare_account.'/rules/lists/'.$list_id.'/items', 'POST', $data, true);

    if($res["success"] == true) {
      log_msg("Banned ".$target);
    }
    else {
      log_msg("Could not ban ".$target, 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
  }
  elseif($action == "unban") {
    $id = false;
    $res = api_request('accounts/'.$cloudflare_account.'/rules/lists/'.$list_id.'/items');

    if($res["success"] == true) {
      foreach($res["result"] as $item) {
        if($item["ip"] == $target) {
          $id = $item["id"];
        }
      }

      if($id == false) {
        log_msg("Could not find ".$target." in list.", 2);
      }
      else {
        $data = '{"items":[{"id":"'.$id.'"}]}';
        $res = api_request('accounts/'.$cloudflare_account.'/rules/lists/'.$list_id.'/items', 'DELETE', $data, 2);

        if($res["success"] == true) {
          log_msg("Unbanned ".$target, 2);
        }
      }
    }
    else {
      log_msg("Could not get list items.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
  }
  elseif($action == "token-test") {
    log_msg("", 1);
    log_msg("=========================", 1);
    log_msg("Cloudlfare API token-test", 1);
    log_msg("=========================", 1);
    log_msg("Testing api token", 1);

    // get token information
    $res = api_request('user/tokens/verify');

    // check result
    if($res["success"] == true && $res["result"]["status"] == "active") {
      log_msg("This API Token is valid and active", 1);
      log_msg("You can now run setup and permission-test", 1);
    }
    else {
      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);
  }
  elseif($action == "setup") {
    log_msg("", 1);
    log_msg("====================", 1);
    log_msg("Cloudlfare API setup", 1);
    log_msg("====================", 1);
    log_msg("Try to list account information", 1);

    // get account information
    $res = api_request('accounts');

    if($res["success"] == true && count($res["result"]) > 0) {
      foreach($res["result"] as $account) {
        log_msg("Found account, ID: ".$account["id"]." Name: ".$account["name"]." Type: ".$account["type"], 1);
      }
    }
    else {
      log_msg("Cant optain account information. Check 'token-test' and token permissions.", 4);
    }

    log_msg("", 1);
    log_msg("Try to list zone id's", 1);

    $res = api_request('zones');

    if($res["success"] == true && count($res["result"]) > 0) {
      foreach($res["result"] as $zone) {
        log_msg("Found zone, ID: ".$zone["id"]." Name: ".$zone["name"]." Status: ".$zone["status"], 1);
      }
    }
    else {
      log_msg("Cant optain zone information. Check 'token-test' and token permissions.", 4);
    }
    log_msg("", 1);
  }
  elseif($action == "permission-test") {
    log_msg("", 1);
    log_msg("==============================", 1);
    log_msg("Cloudlfare API permission-test", 1);
    log_msg("==============================", 1);
    log_msg("permission-test is currently not implemented", 3);
    log_msg("please check your permissions according to the install manual", 3);

    // TODO
  }

  /**
  * cleanup process
  **/
  function cf_cleanup() {
    global $cloudflare_zone, $cloudflare_token, $cloudflare_account;

    // cleanup firewall rule
    log_msg("Check for existing firewall rule", 1);
    $res = api_request('zones/'.$cloudflare_zone.'/firewall/rules');

    if($res["success"] == true) {
      if(count($res["result"]) > 0) {
        foreach($res["result"] as $rule) {
          if($rule["filter"]["description"] == "fail2ban") {
            log_msg("Found old firewall rule, try deleting it.", 1);

            $res = api_request('zones/'.$cloudflare_zone.'/firewall/rules/'.$rule["id"], 'DELETE');
            if($res["success"] == true) {
              log_msg("Firewall rule successfull deleted.", 1);
            }
            else {
              log_msg("Could not delete old firewall rule", 4);
            }
          }
        }
      }
    }
    else {
      log_msg("Could not get firewall information. Check 'token-test' and token permissions.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);

    // cleanup filter rule
    log_msg("Check for existing filter rule", 1);
    $res = api_request('zones/'.$cloudflare_zone.'/filters');

    if($res["success"] == true) {
      if(count($res["result"]) > 0) {
        foreach($res["result"] as $filter) {
          if($filter["ref"] == "fail2ban") {
            log_msg("Found old filter rule, try deleting it.", 1);

            $res = api_request('zones/'.$cloudflare_zone.'/filters/'.$filter["id"], 'DELETE');
            if($res["success"] == true) {
              log_msg("Filter rule successfull deleted.", 1);
            }
            else {
              log_msg("Could not delete old filter rule", 4);
            }
          }
        }
      }
    }
    else {
      log_msg("Could not get filter information. Check 'token-test' and token permissions.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);

    // cleanup lists
    log_msg("Check for existing lists", 1);
    $res = api_request('accounts/'.$cloudflare_account.'/rules/lists');

    if($res["success"] == true) {
      if(count($res["result"]) > 0) {
        foreach($res["result"] as $list) {
          if($list["name"] == "fail2ban") {
            log_msg("Old fail2ban list found, try to delete it.", 1);

            $res = api_request('accounts/'.$cloudflare_account.'/rules/lists/'.$list["id"], 'DELETE');

            if($res["success"] == true) {
              log_msg("Fail2ban list successfull deleted.", 1);
            }
            else {
              log_msg("Could not delete fail2ban list.", 4);

              foreach($res["errors"] as $error) {
                log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
              }
            }
          }
        }
      }
    }
    else {
      log_msg("Could not get list information. Check 'token-test' and token permissions.", 4);

      foreach($res["errors"] as $error) {
        log_msg("Code: ".$error["code"]." Message: ".$error["message"], 4);
      }
    }
    log_msg("", 1);
    log_msg("Cleanup finish", 1);
    log_msg("", 1);
  }

  /**
  * store list id to tmp file
  * to masivly reduce api calls
  *
  * @param string list id
  **/
  function save_lid($list_id) {
    global $tmp_dir;

    $file = @fopen($tmp_dir."fail2ban-list.id", "w+");
    $writen = fwrite($file, $list_id);
    fclose($file);

    return($writen);
  }

  /**
  * get stored list id from tmp file if exist
  *
  * @return string list id
  * @return returns false if file not exist
  **/
  function get_lid() {
    global $tmp_dir;

    if(file_exists($tmp_dir."fail2ban-list.id")) {
      $file = @fopen($tmp_dir."fail2ban-list.id", "r");
      $lid = fgets($file);
      fclose($file);

      return($lid);
    }
    else {
      return false;
    }
  }

  /**
  * make an api request
  *
  * @param string endpoint
  * @param string methode
  * @param array header values
  *
  * @return array json data
  **/
  function api_request($endpoint, $methode = "GET", $post_data = array(), $format_fix = false) {
    global $cloudflare_api_url, $cloudflare_token;

    // generate api endpoint
    $address = $cloudflare_api_url.$endpoint;

    // generate headers
    $headers = array();
    $headers[] = "Authorization: Bearer ".$cloudflare_token;
    $headers[] = "Content-Type:application/json";

    $cf = curl_init();
    curl_setopt($cf, CURLOPT_URL, $address);
    curl_setopt($cf, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($cf, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($cf, CURLOPT_CUSTOMREQUEST, $methode);

    if(is_array($post_data)) {
      if(count($post_data) > 0) {
        if($format_fix == true) {
          curl_setopt($cf, CURLOPT_POSTFIELDS, "[".json_encode($post_data)."]");
        }
        else {
          curl_setopt($cf, CURLOPT_POSTFIELDS, json_encode($post_data));
        }
      }
    }
    else {
      curl_setopt($cf, CURLOPT_POSTFIELDS, $post_data);
    }

    $response = json_decode(curl_exec($cf), true);
    curl_close($cf);

    return($response);
  }

  /**
  * get value from config file
  *
  * @param string config file
  * @param string option name
  *
  * @return string value
  **/
  function get_option($file, $option) {
    global $config_file_path;

    $req_file = $file.".conf";
    $file = $config_file_path.$file;

    if(file_exists($file.".local"))
    {
      $file = @fopen($file.".local", "r");

      while ($line = fgets($file)) {
        if(strpos($line, $option . " = ") !== false) {
          $value = substr($line, strlen($option) + 3);
          break;
        }
      }

      fclose($file);

      if(isset($value)) {
        return rtrim($value, "\r\n");;
      }
    }

    if(file_exists($file.".conf")) {
      $file = @fopen($file.".conf", "r");

      while ($line = fgets($file)) {
        if(strpos($line, $option . " = ") !== false) {
          $value = substr($line, strlen($option) + 3);
          break;
        }
      }

      fclose($file);

      if(isset($value)) {
        return rtrim($value, "\r\n");;
      }
      else {
        log_msg("Could not find config value '".$option."' in '".$req_file.".conf'", 4);
        exit();
      }
    }
    else {
      log_msg("Configurationfile '".$file.".conf' could not be found.", 4);
      exit();
    }
  }

  /**
  * get fail2ban pid id
  *
  * @param string pidfile
  *
  * @return int pid id
  **/
  function get_pid() {
    global $pid_file;

    $file = @fopen($pid_file, "r");
    $pid = fgets($file);
    fclose($file);

    return rtrim($pid, "\r\n");
  }

  /**
  * adding message to fail2ban log
  *
  * @param string log message
  * @param int log level (default INFO if not provided)
  **/
  function log_msg($msg, $level = 1) {
    global $process_id, $log_file;

    $date = date('Y-m-d H:i:s,v', time());

    switch ($level) {
      case 1:
        $formated_level = "INFO    ";
        break;
      case 2:
        $formated_level = "NOTICE  ";
        break;
      case 3:
        $formated_level = "WARNING ";
        break;
      case 4:
        $formated_level = "ERROR   ";
        break;
      case 5:
        $formated_level = "CRITICAL";
        break;
      case 6:
        $formated_level = "DEBUG   ";
    }

    error_log($date." fail2ban.actions        [".$process_id."]: ".$formated_level."[cloudflare] ".$msg."\n", 3 , $log_file);
  }
