#Androguard module for Yara
This module for Yara born inside Koodous project [https://koodous.com](https://koodous.com) and it is able to integrate static APK analysis with Yara. For instance, you can find APKs by package name, permissions or API level... Complete documentation of this module is in Koodous: [http://docs.koodous.com/yara/androguard/](http://docs.koodous.com/yara/androguard/)

## Preparing compilation
You need to re-compile Yara with the androguard module in to be able work with it. To do this, you need to modify some files. The next steps are a summary of official documentation [http://yara.readthedocs.org/en/latest/writingmodules.html#building-our-hello-world](http://yara.readthedocs.org/en/latest/writingmodules.html#building-our-hello-world)

- First of all, include the file **androguard.c** in folder *libyara/modules*.
- Second, we need to say to C compiler and linker that we want to include this module, to do this open the file **libyara/modules/module_list** and add when is used cuckoo **MODULE(androguard)**, resulting something like this:
```
MODULE(pe)
MODULE(elf)
MODULE(math)

#ifdef CUCKOO
MODULE(cuckoo)
MODULE(androguard)
#endif
```

- Modify **libyara/Makefile.am** to add androguard module (in cuckoo block again):
```
MODULES =  modules/tests.c
MODULES += modules/pe.c

if CUCKOO
MODULES += modules/cuckoo.c
MODULES += modules/androguard.c
endif
```

- Recompile Yara, but enabling cuckoo module. The reason to include it is because cuckoo module uses **libjansson** like androguard module, and this is the easy way to prepare all dependencies. If you don't want to include cuckoo module, you can browse for all Makefile files and include libjansson without condition (this is the hard way). So, finally:
```
./bootstrap.sh
./configure --enable-cuckoo
make
make install
```

## Using Androguard module
This androguard module is ready to use with Koodous reports, hence we provide an script called **download_androguard_report.py** (in this repository) to extract this reports automatically.

- First you need to obtain a token from Koodous, to do this, sign in and in your profile options will appear your REST API token, copy it and paste inside the previous script (If you don't have account, registration is free):
```
TOKEN = 'HERE'
```
- Second, use the script:
```Shell
$ python download_androguard_report.py -s d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f

Androguard report saved in d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f-report.json
```
- And finally, use it with Yara!
```Shell
$ yara -x androguard=d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f-report.json rule.yar sample.apk

clicker sample.apk
```