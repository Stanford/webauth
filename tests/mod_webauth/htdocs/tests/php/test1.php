<?php
/*
 * Copyright 2003
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Copying and distribution of this file, with or without modification, are
 * permitted in any medium without royalty provided the copyright notice and
 * this notice are preserved.  This file is offered as-is, without any
 * warranty.
 */
?>

<html>
    <head>
        <title>PHP test1</title>
    </head>

    <body>

        <h1>PHP test1: test from PHP module</h1>
        <hr />
        <p>all the webauth variables can be found in $_SERVER or by calling
            getenv</p>

        <table border="1" cellpadding="3" >
            <tr align="center">
                <th>Name</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>$_SERVER["AUTH_TYPE"]</td>
                <td><?php echo $_SERVER['AUTH_TYPE'] ?></td>
            </tr>
            <tr>
                <td>$_SERVER["REMOTE_USER"]</td>
                <td><?php echo $_SERVER['REMOTE_USER'] ?></td>
            </tr>
            <tr>
                <td>$_SERVER["WEBAUTH_USER"]</td>
                <td><?php echo $_SERVER['WEBAUTH_USER'] ?></td>
            </tr>
            <tr>
                <td>$_SERVER["WEBAUTH_TOKEN_CREATION"]</td>
                <td><?php echo $_SERVER['WEBAUTH_TOKEN_CREATION'] ?></td>
            </tr>
            <tr>
                <td>$_SERVER["WEBAUTH_TOKEN_EXPIRATION"]</td>
                <td><?php echo $_SERVER['WEBAUTH_TOKEN_EXPIRATION'] ?></td>
            </tr>
            <tr>
                <td>getenv("REMOTE_USER")</td>
                <td><?php echo getenv('REMOTE_USER') ?></td>
            </tr>
        </table>

        <hr />
        <p>
            Click <a href="/tests/index.html">here</a> to return without
            logging out<br />
            Click <a href="/tests/logout">here</a> to logout and return
        </p>
        <hr />

<?php
    phpinfo();
?>

    </body>
</html>
