#include <NTL/ZZ.h>
using namespace std;
using namespace NTL;
#include <vector>
#include <cmath>

class cryptography
{
public:
	void diffieHelmann()
	{
		cout << "DIFFIE-HELMANN" << endl;
		ZZ P;
		GenPrime(P, 2048);//Generating a 1mb long prime number
		ZZ PrimRoot = findingPrimeRoot(P);//Generating a prime root 
		cout << endl << endl;
		cout << "Enter Key of Alice:" << endl;
		ZZ Alice;
		cin >> Alice;//Input for key no 1
		cout << "Enter key of Bob:" << endl;
		ZZ Bob;
		cin >> Bob;//Input for key no 2
		ZZ BobKey;
		PowerMod(BobKey, PrimRoot, Bob, P);//Bob's secret key
		ZZ AliceKey;
		PowerMod(AliceKey, PrimRoot, Alice, P);//Alice's secret key
		ZZ Bcode = PowerMod(AliceKey, Bob, P);//Shared secret key
		ZZ Acode = PowerMod(BobKey, Alice, P);//Shared secret key
		cout << endl;
		if (Acode == Bcode)
			cout << "Encrypted" << endl;
		else
			cout << "Not Encrypted" << endl;
		cout << endl;
	}
	void RSA()
	{
		cout << "RSA" << endl;

		ZZ PrimeP, PrimeQ;
		GenPrime(PrimeP, 30);//Generating two large primes
		GenPrime(PrimeQ, 30);//
		cout << endl;
		cout << endl;
		cout << endl;
		ZZ N = PrimeP*PrimeQ;//Finding their Product which is going to be the modulo for our message
		ZZ OofN = (PrimeP - 1)*(PrimeQ - 1);//Finding phi
		ZZ e;
		e = 2;
		while (e < OofN)//finding e
		{
			if (GCD(e, OofN) == 1 && GCD(e, N) == 1)
				break;
			else
			{
				e++;
			}
		}
		ZZ d;
		InvMod(d, e, OofN);//finding d
		cout << "Input Message: "; ZZ inp; cin >> inp;
		system("cls");
		//Taking message input

		//encryption
		ZZ cyphered;
		PowerMod(cyphered, inp, e, N);
		//decrypting
		ZZ decyphered;
		PowerMod(decyphered, cyphered, d, N);
		cout << "Decyphered message:" << decyphered << endl;

	}
	void DigitalSignature()
	{

	}
	void Elgamal()
	{
		cout << "ELGAMAL" << endl;

		//SETUP PHASE
		ZZ P;
		GenPrime(P, 2048);//Prime nb of 1024 bits

		ZZ alpha = findingPrimeRoot(P);//generator of Zp

		//choosing a random private key
		ZZ B;
		B = RandomBnd(P);


		//public key
		ZZ b = PowerMod(alpha, B, P);

		//Publishing (P,alpha,b)

		//ENCRYPTION PHASE
		ZZ X;
		//Taking message to send input
		cout << "Input The Message to send" << endl;
		while (true)
		{
			cin >> X;
			if (X != 0 && X < (P - 1))
			{
				break;
			}
		}
		//system("cls");
		//Taking a random a between range
		ZZ A;
		A = RandomBnd(P);
		//computing ephemeral key
		ZZ ephemeralKey = PowerMod(alpha, A, P);
		//computing shared key

		ZZ K = PowerMod(b, A, P);

		//Computing cyphered text
		ZZ y = MulMod(X, K, P);

		//publishing (ephermeralkey,y)

		//DECRYPTION PHASE
		//computing shared key

		ZZ Kb = PowerMod(ephemeralKey, B, P);

		if (K != Kb)
			cout << "Something's Wrong" << endl;

		//Decrypting
		ZZ j = InvMod(Kb, P);

		ZZ decryptedKey = MulMod(y, j, P);

		cout << "Message:" << decryptedKey << endl;

	}
	struct set
	{
		long long index;
		ZZ points;
	};
	void SecretSharing()
	{
		cout << "SHAMIR SECRET SHARING" << endl;

		cout << "Enter the Secret: "; ZZ secret; cin >> secret;//Taking input a secret
		system("cls");
		cout << "Enter into how many parts you want to divide your secret:"; long long parts; cin >> parts;//Number of data sets to be made
		system("cls");
		cout << "Input from how many parts you require to reconstruct your secret:"; //Number of parts which will be made public
		long long reconstructingParts; cin >> reconstructingParts;
		//Obtaining reconstructingparts-1 random numbers

		vector<ZZ>a(reconstructingParts);//vector containg random numbers(reconstructingparts-1) and secret nb
		a[0] = secret;
		for (long long i = 1; i < reconstructingParts; i++)//generating reconstructingparts-1 random numbers
		{
			a[i] = RandomBnd(secret);
		}
		//[Mathematics] baseexponent = pow(base, exponent)
		ZZ sum;//intermediate variable to store result of points
		long long i;
		long long x = 1;
		long long setx = 1;
		set *sharedpoints = new set[parts + 1];//Declaring data set which will have (1 to parts values and their function values)and at 0th value we'll have our secret
		long long sety = 1;
		while (setx < parts + 1)//loop will run from 1 to parts
		{
			x = 1;
			sum = a[0];
			while (x < reconstructingParts)
			{
				sum += a[x] * pow(sety, x);//calculates f(x)=secret+a[0]*x^1+a[1]*x^2+a[2]*x^3...............a[reconstructingparts]*x^(reconstructingparts-1)
				x++;
			}
			sharedpoints[setx].index = sety;//stores value of x
			sharedpoints[setx].points = sum;//stores value of f(x)=y for x
			sety++;
			setx++;
		}
		sharedpoints[0].index = 0;
		sharedpoints[0].points = secret;
		for (long long j = 1; j < parts + 1; j++)//outputs points generated
		{
			cout << "(" << sharedpoints[j].index << "," << sharedpoints[j].points << ")" << endl;
		}

		set *pointstosend = new set[reconstructingParts];
		for (long long f = 0; f < reconstructingParts; f++)//points to be made public
		{
			pointstosend[f].index = sharedpoints[f + 1].index;
			pointstosend[f].points = sharedpoints[f + 1].points;

		}
		long long sec;
		sec = 0;
		//cout << "Secret:" << secret << endl;
		cout << "Our Secret Mesage:" << answer(pointstosend, reconstructingParts, sec) << endl;
	}
	//function to compute lagrange basis and required secret
	ZZ answer(set *points, long long partsrecieved, long long secret)
	{
		ZZ result;//contains answer
		result = 0;
		for (long long i = 0; i<partsrecieved; i++)//1st loop
		{
			ZZ term = points[i].points;//1st term
			for (long long k = 0; k < partsrecieved; k++)//2nd loop
			{
				if (k != i)
				{
					term = term*(secret - points[k].index) / long double(points[i].index - points[k].index);//term=(x-xk)/(xi-xk)
				}
			}

			result = result + term;
		}
		return (result);

	}
	//Function to find coPrime
	ZZ findingPrimeRoot(ZZ P)
	{
		ZZ checker;
		checker = 0;
		ZZ alpha;
		// Finding g
		while (checker != 1)
		{
			alpha = RandomBnd(P);
			checker = GCD(alpha, P);
		}
		return alpha;
	}

};
void choose();

int main()
{
	choose();
	return 0;
}

void choose()
{
	cryptography test;

	int choice;
	while (true)
	{
		cout << "Press 1 if you want to test Diffie-Helmann Key Exchange Cryptosystem:" << endl;
		cout << "Press 2 if you want to test RSA CryptoSystem:" << endl;
		cout << "Press 3 if you want to test El-Gamal Cryptosystem:" << endl;
		cout << "Press 4 if you want to test Shamir Secret Sharing Cryptosystem:" << endl;
		cout << "Press 0 to quit:" << endl;

		cout << "Input Choice:";
		cin >> choice;
		system("cls");
		if (choice == 1)
		{
			system("cls");
			test.diffieHelmann();
			system("pause");

		}
		else if (choice == 2)
		{
			test.RSA();
			system("pause");
			system("cls");

		}
		else if (choice == 3)
		{
			test.Elgamal();
			system("pause");
			system("cls");


		}
		else if (choice == 4)
		{
			test.SecretSharing();
			system("pause");
			system("cls");

		}
		else if (choice == 0)
			return;
	}
}



