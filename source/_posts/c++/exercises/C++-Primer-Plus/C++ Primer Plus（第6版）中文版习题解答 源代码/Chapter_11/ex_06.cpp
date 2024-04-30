
#include <iostream>
#include "stonewt.h"

const int SIZE = 6;
using namespace std;

int main()
{
    Stonewt stone_arr[SIZE] = {253.6, Stonewt(8, 0.35), Stonewt(23, 0)};
    double input;
    Stonewt eleven = Stonewt(11, 0.0);
    Stonewt max = stone_arr[0];
    Stonewt min = stone_arr[0];
    int num = 0;

    for (int i = 3; i < SIZE; i++)
    {
        cout << "enter the No." << i+1 << "'s element info(in pounds)：" ;
        cin >> input;
        stone_arr[i] = Stonewt(input);
        while(cin.get() != '\n')
            continue;
    }

    for (int i = 0; i < SIZE; i++)
    {
        if (max < stone_arr[i])  max = stone_arr[i];
        if (min > stone_arr[i])  min = stone_arr[i];
        if (stone_arr[i] > eleven)
            num++;
    }

    cout << "The weight max ：";
    max.show_stn();

    cout << "\nThe weight min：";
    min.show_stn();

    cout << "\nHeavy than eleven ：" << num << endl;
    return 0;
}
