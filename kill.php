<?php
$t=`ps ax | grep jazmine_a`;
$r=explode("\n",$t);
foreach ($r as $v)
{
	$x=explode(' ',trim($v));
	$pid = $x[0];
	if ($pid!='')
	$n=`kill $pid`;
	echo $n."\n";
}
