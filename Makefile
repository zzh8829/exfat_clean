target=exfat_clean

main: 
	g++ main.cpp -std=c++11 -o $(target)

clean:
	rm $(target)
