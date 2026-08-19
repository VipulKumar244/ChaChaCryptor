#include<File_crypto.hpp>
#include<iostream>



namespace fs=std::filesystem;
using namespace std::chrono;

namespace{
    void print_usage() {
    std::cout <<
        "pfe -- parallel file encryptor (ChaCha20, chunked, multithreaded)\n\n"
        "Usage:\n"
        "  pfe encrypt <file>      -o <out> --password <pw> [--threads N] [--chunk-size BYTES]\n"
        "  pfe decrypt <file>      -o <out> --password <pw> [--threads N]\n"
        "  pfe encrypt-dir <dir>   --password <pw> [--suffix .pfe] [--threads N] [--chunk-size BYTES]\n"
        "  pfe decrypt-dir <dir>   --password <pw> [--suffix .pfe] [--threads N]\n\n"
        "Notes:\n"
        "  * encrypt-dir/decrypt-dir recurse through <dir> and write a sibling file\n"
        "    per input (input.ext -> input.ext.pfe, and back), leaving the original\n"
        "    untouched. Pass --delete-source to remove the input after success.\n"
        "  * --threads defaults to std::thread::hardware_concurrency().\n";
}
 

struct Args{
    std::string command;
    std::string target;
    std::string output;
    std::string password;
    std::string suffix=".pfe";
    std::uint32_t chunk_size=pfe::kDefaultChunkSize;
    unsigned threads=std::max(1u,std::thread::hardware_concurrency());
    bool delete_source=false;
};

Args parse_args(int argc,char**argv){
    Args a;
    if(argc<3){
        print_usage();
        std::exit(1);
    }
    a.command=argv[1];
    a.target=argv[2];
    for(int i=3;i<argc;i++){
        std::string arg=argv[i];
        auto next=[&]()->std::string{
                if(i+1>=argc){
                    std::cerr<<"Missing value for "<<arg<<"\n";
                    std::exit(1);
                }
                return argv[++i];
        };
        if (arg == "-o" || arg == "--output") a.output = next();
        else if (arg == "--password") a.password = next();
        else if (arg == "--suffix") a.suffix = next();
        else if (arg == "--threads") a.threads = static_cast<unsigned>(std::stoul(next()));
        else if (arg == "--chunk-size") a.chunk_size = static_cast<std::uint32_t>(std::stoul(next()));
        else if (arg == "--delete-source") a.delete_source = true;
        else { std::cerr << "Unknown argument: " << arg << "\n"; print_usage(); std::exit(1); }

    }
     if (a.password.empty()) {
        std::cerr << "--password is required\n";
        std::exit(1);
    }
    if (a.chunk_size % 64 != 0 || a.chunk_size == 0) {
        std::cerr << "--chunk-size must be a positive multiple of 64\n";
        std::exit(1);
    }
    return a;
}

pfe::key derive_key(const std::string&password){
    return pfe::derive_key(password,"pfe-static-salt");//implement random salt
}

void report_error(const fs::path&path,pfe::CryptoError err){
    std::string_view msg;
     switch (err) {
        case pfe::CryptoError::CannotOpenInput: msg = "cannot open input"; break;
        case pfe::CryptoError::CannotCreateOutput: msg = "cannot create output"; break;
        case pfe::CryptoError::BadHeader: msg = "bad header (not a pfe file?)"; break;
        case pfe::CryptoError::UnsupportedVersion: msg = "unsupported file version"; break;
        case pfe::CryptoError::TruncatedInput: msg = "truncated input"; break;
    }
    std::cerr << "  FAILED " << path << ": " << msg << "\n";


}

int run_single(const Args&a){
    if(a.output.empty()){
        std::cerr<<"-o/--output is required for single-file mode\n";
        return 1;
    }
    pfe::ThreadPool pool(a.threads);
    auto key=derive_key(a.password);
    auto t0=steady_clock::now();
    std::expected<void,pfe::CryptoError>result;
    if(a.command=="encrypt")result=pfe::encrypt_file(pool,a.target,a.output,key,a.chunk_size);
    else{
        result=pfe::decrypt_file(pool,a.target,a.output,key);
    }
    auto t1=steady_clock::now();
    if(!result){
        report_error(a.target,result.error());
        return 1;
    }
    auto ms=duration_cast<milliseconds>(t1-t0).count();
        std::cout << a.command << "ed " << a.target << " -> " << a.output
              << " in " << ms << " ms using " << pool.size() << " threads\n";
 
    if (a.delete_source) fs::remove(a.target);
    return 0;

}

int run_directory(const Args&a){
    if(!fs::exists(a.target)||!fs::is_directory(a.target)){
        std::cerr<<"Not a directory: "<<a.target<<"\n";
        return 1;
    }
    bool encrypting=(a.command=="encrypt-dir");
    pfe::ThreadPool pool(a.threads);
    auto key=derive_key(a.password);

    std::vector<fs::path>files;
    for(const auto&entry: fs::recursive_directory_iterator(a.target)){
        if(!entry.is_regular_file())continue;
        auto p=entry.path();
        bool is_pfe=p.extension()==a.suffix;
        if(encrypting&&!is_pfe)files.push_back(p);
        if(!encrypting&&is_pfe)files.push_back(p);
    }

    std::cout << "Found " << files.size() << " file(s) to "
              << (encrypting ? "encrypt" : "decrypt") << " with " << pool.size() << " threads\n";

    auto t0=steady_clock::now();
    int failures=0;
    for(const auto&in_path:files){
        fs::path out_path=encrypting?fs::path(in_path.string()+a.suffix):in_path.parent_path()/in_path.stem();
        std::expected<void,pfe::CryptoError>result;
        if(encrypting){
            result=pfe::encrypt_file(pool,in_path,out_path,key,a.chunk_size);
        }
        else{
            result=pfe::decrypt_file(pool,in_path,out_path,key);
        }
        if(!result){
            report_error(in_path,result.error());
            ++failures;
            continue;
        }
        std::cout <<"ok"<<in_path<<"->"<<out_path<<"\n";
        if (a.delete_source) fs::remove(in_path);
    }
    auto t1=steady_clock::now();
    auto ms=duration_cast<milliseconds>(t1-t0).count();
        std::cout<<(files.size()-failures)<<"/"<<files.size()
              <<" succeeded in "<<ms<<" ms\n";
    return failures == 0 ? 0 : 1;




}



}


int main(int argc,char**argv){
    Args a=parse_args(argc,argv);
    if(a.command=="encrypt"||a.command=="decrypt")return run_single(a);
    if(a.command=="encrypt-dir"||a.command=="decrypt-dir")return run_directory(a);
    print_usage();
    return 1;
}
