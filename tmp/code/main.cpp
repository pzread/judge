#include <iostream>
#include <vector>
#include <math.h>

int ma[1000][1000];
int mb[1000][1000];
int mc[1000][1000];

int main() {
	const std::vector<int> v(1);
	auto a = v[0];        // a has type int
	decltype(v[1]) b = 1; // b has type const int&, the return type of
	//   std::vector<int>::operator[](size_type) const
	auto c = 0;           // c has type int
	auto d = c;           // d has type int
	decltype(c) e;        // e has type int, the type of the entity named by c
	decltype((c)) f = c;  // f has type int&, because (c) is an lvalue
	decltype(0) g;        // g has type int, because 0 is an rvalue

	int i,j,k;
	for(i = 0;i < 1000;i++){
	    for(j = 0;j < 1000;j++){
		ma[i][j] = rand() % 1000;
		mb[i][j] = rand() % 1000;
		mc[i][j] = 0;
	    }
	}

	for(i = 0;i < 1000;i++){
	    for(j = 0;j < 1000;j++){
		for(k = 0;k < 1000;k++){
		    mc[i][j] += ma[i][k] * mb[k][j];	
		}
		if(mc[i][j] < 0){
		    return 0;
		}
	    }
	}

	while(scanf("%d %d",&a,&b) != EOF){
	    std::cout << a+b << std::endl;
	}
}
