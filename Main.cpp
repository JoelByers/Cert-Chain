#include <iostream>
#include "Cert487.h"
#include "CertGroup.h"

using namespace std;

int main(int argc, char** argv){
    CertGroup group;

    for(int i = 1; i < argc; i++){
        Cert487 newCert(argv[i]);
        group.addCert(newCert);
    }

    int start;
    int end;

    cout << "Enter serial numbers of start and end of chain:" << endl;
    cout << "Start: ";
    cin >> start;
    cout << "End: ";
    cin >> end;
    cout << endl;

    if(group.validateChain(start, end)){
        cout << "A valid chain can be found" << endl;
    }
    else{
        cout << "No valid chain can be found" << endl;
    }

    return 0;
}