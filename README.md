# rustwatch
rust based IDS system

This is a project I am doing to learn rust, do not use this as a guide of rust best practive (or even coding best practice) I am very new to Rust and this is a learning experiance. Feedback and pointers are welcome 
Currently it is able to capture traffic on a given network interface and print it onto the screen
<img width="543" alt="image" src="https://user-images.githubusercontent.com/60553334/230187890-8b782dfd-c95d-45eb-9f5a-c5c63435cc75.png">


Not shown it will also now pull the header information to get src and dest ip and port information, 

UPDATE 1
Now have a semi working parser. so far it is very basic and will parse rules to pull out protocal, src and destination ip and ports as well as direction either one way or bi directonally. 

Need to work on tieing it together to filter packets now based on the rules. 

DONE: Will also add in file parseing for rules so they can be stored in a file rather than hard coded 

TODO: 
* refine rule parseing so prints tag if they were alerts/drops etc. 
* add alert severity 