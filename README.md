#Androguard module for Yara
This module for Yara is part of the Koodous project [https://koodous.com](https://koodous.com) and it integrates static APK analysis with Yara. Uou can use it to find APKs by package name, permissions or API level, etc. You can find the documentation for this module in the Koodous documentation's site: [http://docs.koodous.com/yara/androguard/](http://docs.koodous.com/yara/androguard/)

## Preparing compilation
If you want to use this module, first you need to re-compile Yara with the androguard module. To do so, you need to modify some files. Follow the basic steps in the official docs:
[http://yara.readthedocs.org/en/latest/writingmodules.html#building-our-hello-world](http://yara.readthedocs.org/en/latest/writingmodules.html#building-our-hello-world)

- Include the file **androguard.c** in folder *libyara/modules*.
- Modify "**libyara/modules/module_list**" and add "**MODULE(androguard)**" in the cuckoo block. The file should looks like following:
```
MODULE(pe)
MODULE(elf)
MODULE(math)

#ifdef CUCKOO
MODULE(cuckoo)
MODULE(androguard)
#endif
```

- Modify "**libyara/Makefile.am**" to add androguard module ("**MODULES += modules/androguard.c**") in the cuckoo block:
```
MODULES =  modules/tests.c
MODULES += modules/pe.c

if CUCKOO
MODULES += modules/cuckoo.c
MODULES += modules/androguard.c
endif
```

- Recompile Yara, but enabling cuckoo module. The reason to include it is because cuckoo module uses **libjansson** like androguard module, and this is the easy way to prepare all dependencies. If you don't want to include cuckoo module, you have to browse for all Makefile files and include libjansson without condition (this is the hard way).
```
./bootstrap.sh
./configure --enable-cuckoo
make
make install
```

## Using Androguard module
Androguard module is ready to use with Koodous reports, hence we provide an script called **download_androguard_report.py** (inside this repository) to get this reports automatically.

- First you need a Koodous's API token. Create your account, if you don't have one, and access your profile ([https://koodous.com/settings/profile](https://koodous.com/settings/profile)) to get it. Edit **download_androguard_report.py** with your API token.
```
TOKEN = 'HERE'
```
- Use the script with the sha256 of the sample that you refer, in this example is d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f:
```Shell
$ python download_androguard_report.py -s d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f

Androguard report saved in d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f-report.json
```
- And finally, use it with Yara!
```Shell
$ yara -x androguard=d8adb784d08a951ebacf2491442cf90d21c20192085e44d1cd22e2b6bdd4ef5f-report.json rule.yar sample.apk

clicker sample.apk
```
