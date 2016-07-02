#include<iostream>

using namespace std;

int main() {
    int a,b;
    while(cin >> a >> b) {
        if(a == 1 && b == 2) {
            cout << a + b << endl;
        } else {
            cout << a * b << endl;
        }
    }
}
