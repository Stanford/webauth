<?php 

print "<html>";
print "<title>PHP test1</title>";
print "<h2>PHP test1: test from PHP module</h2>";

print "<hr>";
print 'all the webauth variables can be found in $_SERVER or by calling ';
print 'getenv<br><br>';

print '<table border="1" cellpadding="3" >';
print '<tr align=center>';
print '  <th>Name</th>';
print '  <th>Value</th>';
print '</tr>';

print '<tr><td>$_SERVER["AUTH_TYPE"]</td>';
print "<td>".$_SERVER['AUTH_TYPE']."</td></tr>";

print '<tr><td>$_SERVER["REMOTE_USER"]</td>';
print "<td>".$_SERVER['REMOTE_USER']."</td></tr>";

print '<tr><td>$_SERVER["WEBAUTH_USER"]</td>';
print "<td>".$_SERVER['WEBAUTH_USER']."</td></tr>";

print '<tr><td>$_SERVER["WEBAUTH_TOKEN_CREATION"]</td>';
print "<td>".$_SERVER['WEBAUTH_TOKEN_CREATION']."</td></tr>";

print '<tr><td>$_SERVER["WEBAUTH_TOKEN_EXPIRATION"]</td>';
print "<td>".$_SERVER['WEBAUTH_TOKEN_EXPIRATION']."</td></tr>";

print '<tr><td>getenv("REMOTE_USER")</td>';
print "<td>".getenv('REMOTE_USER')."</td></tr>";

print "</table>";
print "<br>";
print "<hr>";
print "<br>";
print 'Click <a href="/tests/index.html">here</a> to return without logging out<br>';
print 'Click <a href="/tests/auth/logout">here</a> to logout and return<br>';
print "<br>";
print "<hr>";
print "<br>";
phpinfo(); 

print "</html>";

?>
