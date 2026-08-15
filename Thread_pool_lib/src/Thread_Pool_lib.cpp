#include<Thread_Pool.hpp>

namespace pfe{
        ThreadPool::ThreadPool(std::size_t worker_count){
        if(worker_count==0)worker_count=1;
        workers_.reserve(worker_count);
        for(std::size_t i=0;i<worker_count;++i){
            workers_.emplace_back([this](std::stop_token stoken){
                worker_loop(stoken);
            });
        }
    }
    ThreadPool::~ThreadPool(){
        for(auto &w:workers_){w.request_stop();}
        cv_.notify_all();
    }

    std::size_t ThreadPool::size()const noexcept{
        return workers_.size();
    }



    void ThreadPool::worker_loop(std::stop_token stoken){

        while(true){
        std::function<void()>task;
        {
            std::unique_lock<std::mutex>lock(mutex_);
            cv_.wait(lock,stoken,[this]{
                return !queue_.empty();
            });

            if(stoken.stop_requested()&&queue_.empty()) return;
            if(queue_.empty())continue;

            task=std::move(queue_.front());
            queue_.pop_front();

        }
        task();
    }
}
}