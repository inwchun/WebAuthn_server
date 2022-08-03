<?php

/*
 * Modified version of https://github.com/lbuchs/WebAuthn/blob/master/_test/server.php
 * Copyright (C) 2018 Lukas Buchs
 * license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 *
 * Server test script for WebAuthn library. Saves new registrations in database.
 *
 *            JAVASCRIPT            |          SERVER
 * ------------------------------------------------------------
 *
 *               REGISTRATION
 *
 *      window.fetch  ----------------->     getCreateArgs
 *                                                |
 *   navigator.credentials.create   <-------------'
 *           |
 *           '------------------------->     processCreate
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 *
 *              VALIDATION
 *
 *      window.fetch ------------------>      getGetArgs
 *                                                |
 *   navigator.credentials.get   <----------------'
 *           |
 *           '------------------------->      processGet
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 */

require_once __DIR__.'/src/WebAuthn.php';
// mysqli_report(MYSQLI_REPORT_ALL);
try {
    $sessid = filter_input(INPUT_GET, 'sessid');
    if($sessid){ 
        session_id($sessid);
        session_start();
    } else {
        session_start([
            "name" => "HPPHPSESSION"
        ]);
    }
    // set_hanpass_db();

    // read get argument and post body
    $fn = filter_input(INPUT_GET, 'fn');
    $requireResidentKey = false;
    $userVerification = "discouraged";

    $userName = filter_input(INPUT_GET, 'userName');
    $userDisplayName = filter_input(INPUT_GET, 'userName');
    $userId = hash('sha256', $userName, true);

    // only support None Format for HanPass
    $formats = array();

    $formats[] = 'none';

    $rpId = 'localhost';
    if ($_GET['rpId']) {
        $rpId = filter_input(INPUT_GET, 'rpId', FILTER_VALIDATE_DOMAIN);
        if ($rpId === false) {
            throw new Exception('invalid relying party ID');
        }
    }

    // any type available
    $typeUsb = 1;
    $typeNfc = 1;
    $typeBle = 1;
    $typeInt = 1;

    // cross-platform: true, if type internal is not allowed
    //                 false, if only internal is allowed
    //                 null, if internal and cross-platform is allowed
    $crossPlatformAttachment = null;

    if (($typeUsb || $typeNfc || $typeBle) && !$typeInt) {
        $crossPlatformAttachment = true;

    } else if (!$typeUsb && !$typeNfc && !$typeBle && $typeInt) {
        $crossPlatformAttachment = false;
    }


    // new Instance of the server library.
    // make sure that $rpId is the domain name.
    $WebAuthn = new lbuchs\WebAuthn\WebAuthn('HanPass Demo', $rpId, $formats);

    // ------------------------------------
    // request for create arguments
    // ------------------------------------

    if ($fn === 'getCreateArgs') {
        $createArgs = $WebAuthn->getCreateArgs($userId, $userName, $userDisplayName, 20, $requireResidentKey, $userVerification, $crossPlatformAttachment);

        header('Content-Type: application/json');
        print(json_encode($createArgs));

        // save challange to session. you have to deliver it to processGet later.
        $_SESSION['challengeCreate'] = $WebAuthn->getChallenge();

    // ------------------------------------
    // request for get arguments
    // ------------------------------------

    } else if ($fn === 'getGetArgs') {
        $cids = array(); 
        $cid = DB_load_cid($userId);
        if($cid == null) {
            http_response_code(400);
        }
        else {
            $cids[] = $cid;
            $getArgs = $WebAuthn->getGetArgs($cids, 20);
            $_SESSION['challengeGet'] = $WebAuthn->getChallenge();
            header('Content-Type: application/json');
            print(json_encode($getArgs));
        }

    } else if ($fn === 'processCreate') {
        $clientDataJSON = base64_decode($_POST['clientDataJSON']);
        $attestationObject = base64_decode($_POST['attestationObject']);
        $challenge = $_SESSION['challengeCreate'];

        // processCreate returns data to be stored for future logins.
        
        $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $userVerification === 'required', true, false);
    
        // // add user infos
        $data->uid = $userId;
        $data->uname = $userName;

        $msg = 'registration success.';
        DB_store($data);

        $return = new stdClass();
        $return->success = true;
        $return->msg = $msg;

        // header('Content-Type: application/json');
        // print(json_encode($return));
        http_response_code(200);

    // ------------------------------------
    // proccess get
    // ------------------------------------

    } else if ($fn === 'processGet') {
        $clientDataJSON = base64_decode($_POST['clientDataJSON']);
        $authenticatorData = base64_decode($_POST['authenticatorData']);
        $signature = base64_decode($_POST['signature']);
        $userHandle = base64_decode($_POST['userHandle']);
        $cid = base64_decode($_POST['id']);
        $challenge = $_SESSION['challengeGet'];
        $credentialPublicKey = DB_load_pk($cid);

        // if we have resident key, we have to verify that the userHandle is the provided userId at registration
        if ($requireResidentKey && $userHandle !== hex2bin($reg->userId)) {
            throw new \Exception('userId doesnt match (is ' . bin2hex($userHandle) . ' but expect ' . $reg->userId . ')');
        }

        // process the get request. throws WebAuthnException if it fails
        $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, $userVerification === 'required');

        $return = new stdClass();
        $return->success = true;
        http_response_code(200);
    } 
    
} catch (Throwable $ex) {
    $return = new stdClass();
    $return->success = false;
    $return->msg = $ex->getMessage();
    session_destroy();
    header('Content-Type: application/json');
    http_response_code(400);
    print(json_encode($return));
}