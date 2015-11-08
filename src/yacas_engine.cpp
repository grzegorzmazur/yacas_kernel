/*
 * This file is part of yacas_kernel.
 * Yacas is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesset General Public License as
 * published by the Free Software Foundation, either version 2.1
 * of the License, or (at your option) any later version.
 *
 * Yacas is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with yacas_kernel.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

/* 
 * File:   yacas_engine.cpp
 * Author: mazur
 *
 * Created on November 7, 2015, 12:52 PM
 */

#include <jsoncpp/json/writer.h>

#include "yacas_engine.hpp"

YacasEngine::YacasEngine(const std::string& scripts_path, const zmqpp::context& ctx, const std::string& endpoint):
    _yacas(_side_effects),
    _socket(ctx, zmqpp::socket_type::pair)
{
    _yacas.Evaluate(std::string("DefaultDirectory(\"") + scripts_path + std::string("\");"));
    _yacas.Evaluate("Load(\"yacasinit.ys\");");
    
    _socket.connect(endpoint);
    
    _worker_thread = new std::thread(std::bind(&YacasEngine::_worker, this));
}

void YacasEngine::submit(unsigned long id, const std::string& expr)
{
    const TaskInfo ti = {id, expr};
    
    std::lock_guard<std::mutex> lock(_mtx);
    _tasks.push_back(ti);
    _cv.notify_all();
}

void YacasEngine::_worker()
{
    for (;;) {
        TaskInfo ti;
        
        {
            std::unique_lock<std::mutex> lock(_mtx);
    
            while (_tasks.empty())
                _cv.wait(lock);
            
            ti = _tasks.front();
            _tasks.pop_front();
        }
        
        _side_effects.clear();
        _side_effects.str("");

        _yacas.Evaluate((ti.expr + ";"));

        Json::Value v;
        v["id"] = Json::Value::UInt64(ti.id);
        
        if (_yacas.IsError())
            v["error"] = _yacas.Error();
        else
            v["result"] = _yacas.Result();
            
        v["side_effects"] = _side_effects.str();
        
        
        zmqpp::message msg;
        msg << Json::writeString(Json::StreamWriterBuilder(), v);
        _socket.send(msg);
    }
}
