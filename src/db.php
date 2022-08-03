<?php

require_once 'constants.php';

function connect_db() {
    return new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
}

function set_hanpass_db() {
    $db = connect_db();
    $db->query("CREATE TABLE IF NOT EXISTS `User` ( 
        `uid` binary(" . USERID_LENGTH . "),
        `uname` varchar(" . USERNAME_LENGTH . "),
        `cid` binary(" . CID_LENGTH . "),
        `pk` char(" . PK_LENGTH . "),
        PRIMARY KEY  (`uid`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    );
    error_log($db->error);
    $db->close();
}

function DB_store($data) {
    $pk = $data->pk;
    $pk = str_replace("-----BEGIN PUBLIC KEY-----", "", $pk);
    $pk = str_replace("-----END PUBLIC KEY-----", "", $pk);
    $pk = str_replace("\n", "", $pk);
    $pk = str_replace("\r", "", $pk);
    $db = connect_db();
    error_log(strlen($data->cid));
    $db->query("INSERT INTO `User` (`uid`, `uname`, `cid`, `pk`) VALUES (
        '$data->uid', '$data->uname' , '$data->cid', '$pk')
        ON DUPLICATE KEY UPDATE uname='$data->uname', cid='$data->cid',
        pk='$pk'");
    $db->close();
}

function DB_load_cid($uid) {
    $db = connect_db();
    $res = $db->query("SELECT * FROM `User` WHERE uid = '$uid'");
    $db->close();
    $row = $res->fetch_assoc();
    if($row == null)
        return null;
    else
        return $row['cid'];
}

function DB_load_pk($cid) {
    $db = connect_db();
    $res = $db->query("SELECT * FROM `User` WHERE cid = '$cid'");
    $db->close();
    $row = $res->fetch_assoc();
    $pk_str = $row['pk'];
    $pk = "-----BEGIN PUBLIC KEY-----\n". substr($pk_str, 0, 64) . "\n" . substr($pk_str, 64). "\n-----END PUBLIC KEY-----";
    return $pk;
}   
?>