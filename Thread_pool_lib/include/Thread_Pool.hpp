#include<condition_variable>
#include<deque>
#include<functional>
#include<future>
#include<mutex>
#include<stop_token>
#include<thread>
#include<vector>




namespace pfe{

    class ThreadPool{
        public:
            explicit ThreadPool(std::size_t worker_count);
            ThreadPool(const ThreadPool& other)=delete;
            ThreadPool& operator=(const ThreadPool& other)=delete;
            ThreadPool(const ThreadPool&& other)=delete;
            ThreadPool& operator=(const ThreadPool&&other)=delete;
            ~ThreadPool();

            std::size_t size() const noexcept;

            template<class F,class R=std::invoke_result_t<F>>
            auto submit(F task)->std::future<R>{
            auto packaged=std::make_shared<std::packaged_task<R()>>(
            std::move(task)
            );
            std::future<R>fut=packaged->get_future();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.emplace_back([packaged]{
                (*packaged)();
            });

        }

        cv_.notify_one();
        return fut;

     }   





        private:
            void worker_loop(std::stop_token stoken);
            std::vector<std::jthread>workers_;
            std::deque<std::function<void()>>queue_;
            std::mutex mutex_;
            std::condition_variable_any cv_;

    



    };

}