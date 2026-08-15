#include<Thread_Pool.hpp>
#include<iostream>
#include<assert.h>

int main(){
    pfe::ThreadPool pool(4);
    std::atomic<int> shared_counter{0};

    //std::vector<std::future<void>>standard_futures;
    std::vector<std::future<void>>standard_futures;

    for(int i=0;i<1000;i++){
        standard_futures.emplace_back(std::move(pool.submit(
            [&shared_counter](){
                shared_counter.fetch_add(1,std::memory_order_relaxed);
            }
        )));
    }

     auto malicious_future = pool.submit([]() -> void {
        throw std::runtime_error("Surfaced Exception: Thread execution failure handled safely.");
    });

    for(auto&fut:standard_futures){
        fut.get();
    }

    assert(shared_counter.load()==1000);
    std::cout<<shared_counter.load()<<"\n";

    bool c=false;
    try{
        malicious_future.get();
    }catch(const std::runtime_error& err){
        c=true;
        std::cout<<"caught mal\n";

    }
    return 0;


}