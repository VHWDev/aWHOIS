<?php
/*
aWHOIS checker
Powered by unirest.io and https://www.mashape.com/nametoolkit
Version 1.0

Vincent's WHOIS checker allows different options to compare and check WHOIS results
Copyright (C) 2013  Vincent van Daal (http://vincentvandaal.nl)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

/*
Requirements: sessions should be working on your environment, port 80 should be allowed in regards to making an connection to the API of mashape.com
*/

// Change the mashape_api_key string to your Mashape Authentication code for nametoolkit (https://www.mashape.com/nametoolkit) -- USE YOUR PRODUCTION KEY
define('mashape_api_key', 'ENTER_YOUR_MASHAPE_NAMETOOLKIT_PRODUCTION_KEY_HERE');

/*
STOP EDITING BELOW THIS LINE UNLESS YOU KNOW WHAT YOU'RE DOING

@todo Comment functions and class
@todo Implement alternative API's as well (as back-up and or choice by end user)
@todo Maybe split up code to several files
@todo Maybe use a template engine
@todo Better error handling and debugging
*/

session_start();

require_once './lib/Unirest.php';

class aWHOIS extends Unirest
{	
	public function getWhois($url = '')
	{
		$domain = $url;
		
		$response = Unirest::get(
		"https://nametoolkit-name-toolkit.p.mashape.com/beta/whois/".$domain."",
		array(
			"X-Mashape-Authorization" => mashape_api_key
		));
		
		// Get json_decoded array from raw_body
		$wda = json_decode($response->raw_body, true);
		
		$debug = print_r($wda, true);
		
		if(!isset($wda['available']))
		{
			$array_fail_images = array('http://i.imgur.com/7PZrLpI.gif', 'http://i.imgur.com/9xcZt.gif', 'http://i.imgur.com/4XuNayo.gif', 'http://i.imgur.com/jFC16gR.gif', 'http://i.imgur.com/2wRCQv7.gif', 'http://i.imgur.com/QzDOmLv.gif', 'http://wac.450f.edgecastcdn.net/80450F/thefw.com/files/2013/02/cat-one.gif', 'http://wac.450f.edgecastcdn.net/80450F/thefw.com/files/2013/02/exercise.gif', 'http://wac.450f.edgecastcdn.net/80450F/thefw.com/files/2013/02/zoidberg.gif');
			echo '<h3>WHOIS for '.$domain.'</h3><p>Failure while checking WHOIS for '.$domain.'</p><p><img src="'.$array_fail_images[mt_rand(0,count($array_fail_images))].'"></p><p style="visibility: hidden; display: none;">Debugging information: '.htmlspecialchars($response->raw_body).'</p>';
			/*echo 'Trying RoboWhois instead...';
			
			echo print_r($this->robowhois($domain));*/
		}
		else
		{
			// Nice text formatting stuff
			$available = ($wda['available']) ? 'Available for registration' : 'Not available (registered)';
			$registrarurl = (empty($wda['registrar']['url'])) ? '' : '(<a href="'.$wda['registrar']['url'].'" target="_blank">'.$wda['registrar']['url'].'</a>)';
			
			$nameserversA = array();
			foreach ($wda['nameservers'] as $key => $value)
			{
				$nameserversA[] = $wda['nameservers'][$key]['name'];
			}
			$nameservers = implode(", ", $nameserversA);
			
			if(is_array($wda['registrant_contacts']))
			{
				$registrantA = array();
				foreach ($wda['registrant_contacts'] as $key => $value)
				{
					foreach($value as $value2 => $key)
					{
						$key = (empty($key)) ? '--' : $key;
						$registrantA[] = '&emsp;'.$value2.': '.$key.'';
					}
				}
				$registrant_contacts = implode("<br>", $registrantA);
			}
			else
			{
				$registrant_contacts = 'Not disclosed';
			}
			
			if(is_array($wda['admin_contacts']))
			{
				$admin_contactsA = array();
				foreach ($wda['admin_contacts'] as $key => $value)
				{
					foreach($value as $value2 => $key)
					{
						$key = (empty($key)) ? '--' : $key;
						$admin_contactsA[] = '&emsp;'.$value2.': '.$key.'';
					}
				}
				$admin_contacts = implode("<br>", $admin_contactsA);
			}
			else
			{
				$admin_contacts = 'Not disclosed';
			}
			
			if(is_array($wda['technical_contacts']))
			{
				$technical_contactsA = array();
				foreach ($wda['technical_contacts'] as $key => $value)
				{
					foreach($value as $value2 => $key)
					{
						$key = (empty($key)) ? '--' : $key;
						$technical_contactsA[] = '&emsp;'.$value2.': '.$key.'';
					}
				}
				$technical_contacts = implode("<br>", $technical_contactsA);
			}
			else
			{
				$technical_contacts = 'Not disclosed';
			}
			
			$html = '<h3>WHOIS for '.$domain.'</h3>
			<p>
			<strong>Available:</strong> '.$available.'<br>
			<strong>Status:</strong> '.$wda['status'].'<br>
			<strong>Last updated:</strong> '.$wda['updated_on'].'<br>
			<strong>Registar:</strong> '.$wda['registrar']['name'].' '.$registrarurl.'<br>
			<strong>Nameservers:</strong> '.$nameservers.'<br>
			<strong>Registrant contacts:</strong><br> '.$registrant_contacts.'<br>
			<strong>Admin contacts:</strong><br> '.$admin_contacts.'<br>
			<strong>Technical contacts:</strong><br> '.$technical_contacts.'</p>';
			
			/*
			$html .= '<div>
				<p><small><a href="#debug">Raw response</a></small></p>
				<p>'.$response->raw_body.'</p>
			</div>';
			*/
			
			return $html;
			
			
		}
	}
	
	public function GenerateCSFRToken()
	{
		$_SESSION['CSFRToken'] = md5(uniqid(rand(), TRUE));
		return $_SESSION['CSFRToken'];
	}
	
	public function CheckCSFRToken($token = '')
	{
		if(!isset($_SESSION['CSFRToken']) || empty($_SESSION['CSFRToken']) || empty($token) || $token != $_SESSION['CSFRToken'])
		{
			return false;
		}
		else
		{
			unset($_SESSION['CSFRToken']);
			return true;
		}
	}
	
	public function HeaderHTML()
	{
		$headerhtml = '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>aWHOIS Checker</title>
<link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.min.css" rel="stylesheet">
<style>
html,
body {
	height: 100%;
}

#wrap {
	min-height: 100%;
	height: auto !important;
	height: 100%;
	margin: 0 auto -61px;
}

#push,
#footer {
	height: 60px;
}
#footer {
	background-color: #f5f5f5;
	border-top: 1px solid #e5e5e5;
	text-align: center;
}

@media (max-width: 767px) {
	#footer {
		margin-left: -20px;
		margin-right: -20px;
		padding-left: 20px;
		padding-right: 20px;
	}
}

.container {
	width: auto;
	max-width: 680px;
	//padding: 0 15px;
}
.container .credit {
	margin: 20px 0;
}

#URLsInput {
	width: 98%;
}

#doURLsCheck {
	width: 200px;
}

</style>
<script src="http://code.jquery.com/jquery.js"></script>
</head>

<body>
<div id="wrap">
	<div class="container">
		<div class="page-header">
          <h1><a href="index.php">aWHOIS Checker</a></h1>
        </div>';
		
		return $headerhtml;
	}
	
	public function UrlFormHTML($extramessage = '')
	{
		$token = $this->GenerateCSFRToken();
		
		$formhtml = sprintf('<div>
		<p>
			%s
			<form method="post">
				<textarea name="urls" class="form-control" rows="8" id="URLsInput" placeholder="Enters URLs here, each URL on a new line. (max 200)"></textarea>
				<input type="hidden" name="appcode" value="%s">
				<input type="submit" id="doURLsCheck" class="btn btn-primary btn-lg btn-block" value="Check URLs">
			</form>
		</p>
	</div>', $extramessage, $token);
		
		return $formhtml;
	}
	
	public function FooterHTML()
	{
		$footerhtml = '<div id="push"></div>
	</div>
</div>
<div id="footer">
	<div class="container">
		<p class="text-muted credit">©2013 - <a href="http://vincentvandaal.nl">Vincent van Daal</a> - <a href="http://www.gnu.org/licenses/gpl-3.0.html">GPLv3 License</a>.</p>
	</div>
</div>
<script src="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/js/bootstrap.min.js"></script>
<script>
/*! matchMedia() polyfill - Test a CSS media type/query in JS. Authors & copyright (c) 2012: Scott Jehl, Paul Irish, Nicholas Zakas. Dual MIT/BSD license */
/*! NOTE: If you\'re already including a window.matchMedia polyfill via Modernizr or otherwise, you don\'t need this part */
window.matchMedia=window.matchMedia||function(a){"use strict";var c,d=a.documentElement,e=d.firstElementChild||d.firstChild,f=a.createElement("body"),g=a.createElement("div");return g.id="mq-test-1",g.style.cssText="position:absolute;top:-100em",f.style.background="none",f.appendChild(g),function(a){return g.innerHTML=\'&shy;<style media="\'+a+\'"> #mq-test-1 { width: 42px; }</style>\',d.insertBefore(f,e),c=42===g.offsetWidth,d.removeChild(f),{matches:c,media:a}}}(document);

/*! Respond.js v1.1.0: min/max-width media query polyfill. (c) Scott Jehl. MIT/GPLv2 Lic. j.mp/respondjs  */
(function(a){"use strict";function x(){u(!0)}var b={};if(a.respond=b,b.update=function(){},b.mediaQueriesSupported=a.matchMedia&&a.matchMedia("only all").matches,!b.mediaQueriesSupported){var q,r,t,c=a.document,d=c.documentElement,e=[],f=[],g=[],h={},i=30,j=c.getElementsByTagName("head")[0]||d,k=c.getElementsByTagName("base")[0],l=j.getElementsByTagName("link"),m=[],n=function(){for(var b=0;l.length>b;b++){var c=l[b],d=c.href,e=c.media,f=c.rel&&"stylesheet"===c.rel.toLowerCase();d&&f&&!h[d]&&(c.styleSheet&&c.styleSheet.rawCssText?(p(c.styleSheet.rawCssText,d,e),h[d]=!0):(!/^([a-zA-Z:]*\/\/)/.test(d)&&!k||d.replace(RegExp.$1,"").split("/")[0]===a.location.host)&&m.push({href:d,media:e}))}o()},o=function(){if(m.length){var b=m.shift();v(b.href,function(c){p(c,b.href,b.media),h[b.href]=!0,a.setTimeout(function(){o()},0)})}},p=function(a,b,c){var d=a.match(/@media[^\{]+\{([^\{\}]*\{[^\}\{]*\})+/gi),g=d&&d.length||0;b=b.substring(0,b.lastIndexOf("/"));var h=function(a){return a.replace(/(url\()[\'"]?([^\/\)\'"][^:\)\'"]+)[\'"]?(\))/g,"$1"+b+"$2$3")},i=!g&&c;b.length&&(b+="/"),i&&(g=1);for(var j=0;g>j;j++){var k,l,m,n;i?(k=c,f.push(h(a))):(k=d[j].match(/@media *([^\{]+)\{([\S\s]+?)$/)&&RegExp.$1,f.push(RegExp.$2&&h(RegExp.$2))),m=k.split(","),n=m.length;for(var o=0;n>o;o++)l=m[o],e.push({media:l.split("(")[0].match(/(only\s+)?([a-zA-Z]+)\s?/)&&RegExp.$2||"all",rules:f.length-1,hasquery:l.indexOf("(")>-1,minw:l.match(/\(\s*min\-width\s*:\s*(\s*[0-9\.]+)(px|em)\s*\)/)&&parseFloat(RegExp.$1)+(RegExp.$2||""),maxw:l.match(/\(\s*max\-width\s*:\s*(\s*[0-9\.]+)(px|em)\s*\)/)&&parseFloat(RegExp.$1)+(RegExp.$2||"")})}u()},s=function(){var a,b=c.createElement("div"),e=c.body,f=!1;return b.style.cssText="position:absolute;font-size:1em;width:1em",e||(e=f=c.createElement("body"),e.style.background="none"),e.appendChild(b),d.insertBefore(e,d.firstChild),a=b.offsetWidth,f?d.removeChild(e):e.removeChild(b),a=t=parseFloat(a)},u=function(b){var h="clientWidth",k=d[h],m="CSS1Compat"===c.compatMode&&k||c.body[h]||k,n={},o=l[l.length-1],p=(new Date).getTime();if(b&&q&&i>p-q)return a.clearTimeout(r),r=a.setTimeout(u,i),void 0;q=p;for(var v in e)if(e.hasOwnProperty(v)){var w=e[v],x=w.minw,y=w.maxw,z=null===x,A=null===y,B="em";x&&(x=parseFloat(x)*(x.indexOf(B)>-1?t||s():1)),y&&(y=parseFloat(y)*(y.indexOf(B)>-1?t||s():1)),w.hasquery&&(z&&A||!(z||m>=x)||!(A||y>=m))||(n[w.media]||(n[w.media]=[]),n[w.media].push(f[w.rules]))}for(var C in g)g.hasOwnProperty(C)&&g[C]&&g[C].parentNode===j&&j.removeChild(g[C]);for(var D in n)if(n.hasOwnProperty(D)){var E=c.createElement("style"),F=n[D].join("\n");E.type="text/css",E.media=D,j.insertBefore(E,o.nextSibling),E.styleSheet?E.styleSheet.cssText=F:E.appendChild(c.createTextNode(F)),g.push(E)}},v=function(a,b){var c=w();c&&(c.open("GET",a,!0),c.onreadystatechange=function(){4!==c.readyState||200!==c.status&&304!==c.status||b(c.responseText)},4!==c.readyState&&c.send(null))},w=function(){var b=!1;try{b=new a.XMLHttpRequest}catch(c){b=new a.ActiveXObject("Microsoft.XMLHTTP")}return function(){return b}}();n(),b.update=n,a.addEventListener?a.addEventListener("resize",x,!1):a.attachEvent&&a.attachEvent("onresize",x)}})(this);
</script>
</body>
</html>';

		return $footerhtml;
	}
} // End of class

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

// Start new instance of class aWhois
$aWHOIS = new aWHOIS();

// We use a seperate GET request later from within JQuery to actually fetch the results and prevent the page from timing out and waiting too long.
if($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['url']) && ($_GET['rc'] === $_SESSION['request_code']))
{
	if(empty($_GET['url']))
	{
		echo '<div class="danger"><p>No URL given.</p></div>';
	}
	else
	{
		$domainname = $_GET['url'];
		echo $aWHOIS->getWhois($domainname);
	}
}
// If request is not GET we either show the page pending the WHOIS results or the form to actually enter the URLs to enter.
else
{
	// Display Header HTML
	echo $aWHOIS->HeaderHTML();

	// Check if URLs are submitted
	if($_SERVER['REQUEST_METHOD'] === "POST" && isset($_POST['urls'], $_POST['appcode']))
	{
		if($aWHOIS->CheckCSFRToken($_POST['appcode']) === false)
		{
			// Display UrlFormHTML for entering actual domains to check with an extra message that the CSFR token is incorrect.
			echo $aWHOIS->UrlFormHTML('<div class="alert alert-error"><p>Security check failed, do not refresh the page when submitting URLs.</p></div>');
		}
		elseif(empty($_POST['urls']))
		{
			// Display UrlFormHTML for entering actual domains to check with an extra message that the CSFR token is incorrect.
			echo $aWHOIS->UrlFormHTML('<div class="alert alert-error"><p>No URLs entered, please enter the URLs to display the WHOIS results from, each URL should be entered on a new line.</p></div>');
		}
		else
		{
			unset($_SESSION['request_code']);
			
			$checkArray = preg_split('/\n|\r/', $_POST['urls'], -1, PREG_SPLIT_NO_EMPTY);
			
			if(count(array_unique($checkArray)) < count($checkArray))
			{
				$checkArray = array_unique($checkArray);
				
				if(count(array_unique($checkArray)) <= 200) // 200 Max
				{
					echo '<div class="alert alert-success"><p>Processing '.count($checkArray).' URLs.</p></div>';
					echo '<div class="alert alert-warning"><p>Ignored '.count(array_unique($checkArray)).' duplicate URL(s)</p></div>';
					
					$requestcode = md5(uniqid(rand(), TRUE));
					$_SESSION['request_code'] = $requestcode;
					
					$i = 0;
					foreach($checkArray as $key => $domainname)
					{
						$i++;
						
						printf('
						<div id="%1$d-wcd"><h2>%2$s</h2>
						<img src="http://i.stack.imgur.com/FhHRx.gif"> Loading result, please wait and do not close this page...
						</div>
						<script>$(\'#%1$d-wcd\').load(\'index.php?url=%2$s&rc=%3$s\');</script>
						', $i, $domainname, $requestcode);
					}
					
					echo '<hr>
					<p><a href="index.php">Need to check more? Click here.</a></p>';
				}
				else
				{
					echo $aWHOIS->UrlFormHTML('<div class="alert alert-error"><p>Exceeded max number of 200 URLs</p></div>');
				}
			}
			else
			{
				if(count($checkArray) <= 200) // 200 Max
				{
					echo '<div class="alert alert-success"><p>Processing '.count($checkArray).' URLs.</p></div>';
					
					$requestcode = md5(uniqid(rand(), TRUE));
					$_SESSION['request_code'] = $requestcode;
					
					$i = 0;
					foreach($checkArray as $key => $domainname)
					{
						$i++;
						
						printf('
						<div id="%1$d-wcd"><h2>%2$s</h2>
						<img src="http://i.stack.imgur.com/FhHRx.gif"> Loading result, please wait and do not close this page...
						</div>
						<script>$(\'#%1$d-wcd\').load(\'index.php?url=%2$s&rc=%3$s\');</script>
						', $i, $domainname, $requestcode);
					}
					
					echo '<hr>
					<p><a href="index.php">Need to check more? Click here.</a></p>';
				}
				else
				{
					echo $aWHOIS->UrlFormHTML('<div class="alert alert-error"><p>Exceeded max number of 200 URLs</p></div>');
				}
			}
		}
	}
	else
	{
		// Display UrlFormHTML for entering actual domains to check
		echo $aWHOIS->UrlFormHTML();
	}

	// Display HTML footer
	echo $aWHOIS->FooterHTML();
}
?>
