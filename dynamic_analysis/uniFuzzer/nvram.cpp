// #include <algorithm>
#include <map>
#include <string>
#include <cstring>
extern "C"{
    std::map <std::string, std::string> nvram;
    int nvram_init(){

    }
    int nvram_set(const char * key,const char * value){
        std::string nvram_key(key);
        std::string nvram_value(value);
        nvram[key]=value;
    }
    char* nvram_get(const char * key){
        std::string nvram_key(key);
        auto iter = nvram.find(nvram_key);
        if (iter!=nvram.end()){
            // find the key-value, return the value
            char *buf = (char*)malloc((iter->second).length() + 1);
            strcpy(buf, (iter->second).c_str());
            return buf;
        }
        else{
            return NULL;
        }
    }
}