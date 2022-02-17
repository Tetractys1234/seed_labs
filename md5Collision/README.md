* MD5 Collision Attack Lab *
------------------------------------

*** Intro

"A secure one-way hash function needs to satisfy two properties: the one-way property and the collision-resistance property. The One-way property ensures that a given hash value is computationally infeasible to find two different inputs X and Y such that hash(X) = y. The collision-resistance property ensures that it is computationally ineasible to find two different inputs X and Y such that hash(X) = hash(Y)" [Source](https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_MD5_Collision/Crypto_MD5_Collision.pdf)

The objective of this write-up following the SEED-lab exercise is to gain an understanding of the impact of collision attacks on hash fucntions. 

*** Lab Environment

Ubuntu 20.X VM 

"Fast MD5 collision Generation" [Program](https://www.win.tue.nl/hashclash/)


*** Lab Tasks

**** Task 1: Generating Two Different Files with the Same MD5 Hash:

Using the program provided with the seed lab setup ,MD5collgen, we create two files out1.bin and out2.bin whose contents differ, but the MD5sum of the two files is exactly the same

![diffbutsame](img/diffbutsame.png)

