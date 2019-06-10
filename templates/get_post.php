<?php
    class MyDB extends SQLite3
    {
        function __construct()
        {
            $this->open('webapp.db')
        }
    }
    $db = new MyDb();
    if(!$db){
        echo $db->lastErrorMsg();
    }else{
        echo "Open database successfully\n";
    }

    $res = $db->querry('SELECT * FROM broadcasts ORDER BY time_sent DESC');

    if(!$res){
        echo $db->lastErrorMsg();
    }else{
        echo "read data\n"
        while ($row = $res->fetchArray()) {
            echo "{$row['id']} {$row['name']} {$row['price']} \n";
        }
    }

    $db->close();
?>