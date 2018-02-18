<?php
$a=array();

//newblock test
$a['command']='newblock';

$a['sig'] = "TGgydaZiR0gJxw5c40BY3GcHCD3Tax8+ABlhYgrmqyH/EsRUwaTFAVIMfkjtMQSr7tYpkqta6xF5+dV/Zf/9BQ==";
$a['data'] = "W2EI8cS4DUGBoDqJmPng5g091xCsntku1n8sEv7iyp+4np82MEy/515cPwm+/w6X4ZtduGnijvntUi/GD1YljwxcNsk=";
$a['sendaddr'] = "jaz_uHXcLpDXEuR6nu2N+/WwYxce3SKbGuXe8ZXWKtzJXUAa9or9ZjnmLaBZBLHYKuZ1fUTGmRvt9EYasdRPCYIJnw==";
$a['recvaddr'] = "jaz4wuYRXMPDxjpqu5L6P6MJJ8Zjs6d1SMG5rJC4UTZbmbw7hCvn2Y9biZjiED6qcHzvgS4G2FEfVMgKDXRgY558kjZ";
$a['ttl']=0;
$a['data_key'] = "nada";
echo json_encode($a);
echo "\n\n";

//getblock test

$a = array();
$a['command']='getblock';
$a['blockid']=7;

echo json_encode($a);

echo "\n\n";

$a = array();
$a['command']='validate';
$a['blockid']=7;

echo json_encode($a);

echo "\n\n";

