rule WD_Botnet_C2_Generic
{
  meta:
    author = "WD CYBER TOOLKIT NEO"
    description = "Generic botnet/C2 string set for lab validation"
  strings:
    $a = "botnet" nocase
    $b = "irc.recv" nocase
    $c = "cmd.exe /c" nocase
    $d = "/gate.php" nocase
  condition:
    2 of them
}

rule WD_CryptoMiner_Indicators
{
  meta:
    author = "WD CYBER TOOLKIT NEO"
    description = "Crypto-miner markers"
  strings:
    $a = "stratum+tcp://" nocase
    $b = "xmrig" nocase
    $c = "--donate-level" nocase
  condition:
    any of them
}

rule WD_Webshell_Small
{
  meta:
    author = "WD CYBER TOOLKIT NEO"
    description = "Minimal PHP webshell markers"
  strings:
    $a = "eval($_POST" nocase
    $b = "system($_GET" nocase
    $c = "passthru($_REQUEST" nocase
  condition:
    any of them
}
