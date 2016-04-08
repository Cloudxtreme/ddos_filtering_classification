<?php
$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$fileType = pathinfo($target_file,PATHINFO_EXTENSION);

echo '<h1 align="center">DDoS Filtering Tool</h1>';

// if (file_exists($target_file)) {
//     echo "The file \"" . basename( $_FILES["fileToUpload"]["name"]). "\" was already analysed. <br/>";
//     $uploadOk = 0;
// }
// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
    echo "Sorry, your file is too large.<br />";
    $uploadOk = 0;
}
// Allow certain file formats
if($fileType != "pcap" && $fileType != "pcapng") {
    echo "Sorry, only PCAP, PCAPNG, & NFDUMP files are allowed.<br />";
    $uploadOk = 0;
}
// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
    //echo "Sorry, your file was not uploaded.<br />";
// if everything is ok, try to upload file
} 
else {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "<center>Please wait! We are analysing your \"". basename( $_FILES["fileToUpload"]["name"]). "\" file.<br/>The waiting time can be up to 10 min depending on the file size.</center>";
        echo '<div align="center"> <img src="figs/processing.gif" alt="Processing" align="center"> </div>';
        shell_exec('./ddos_filtering.sh');
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}
?>