docs/index.html: XsrfProtection.php
	rm -rf docs/*
	phpdoc -f XsrfProtection.php -t docs -o HTML:Smarty:PHP
