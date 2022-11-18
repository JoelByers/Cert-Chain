#include <iostream>
#include "Cert487.h"
#include "CertGroup.h"

using namespace std;

int main(){
    Cert487 bobCert("bob.txt");
    Cert487 aliceCert("alice.txt");
    Cert487 carlCert("carl.txt");

    aliceCert.printLess();
    cout << endl;
    bobCert.printLess();
    cout << endl;
    carlCert.printLess();
    CertGroup group;
    group.addCert(bobCert);
    group.addCert(aliceCert);
    group.addCert(carlCert);
    cout << group.validateChain(1,3) << endl;

    return 0;
}