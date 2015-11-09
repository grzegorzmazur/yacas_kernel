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
 * File:   yacas_kernel.hpp
 * Author: mazur
 *
 * Created on November 6, 2015, 3:10 PM
 */

#ifndef YACAS_KERNEL_HPP
#define YACAS_KERNEL_HPP

#include "hmac_sha256.hpp"
#include "yacas_engine.hpp"

#include <boost/uuid/random_generator.hpp>
#include <jsoncpp/json/json.h>
#include <zmqpp/zmqpp.hpp>

#include <map>
#include <sstream>

class YacasKernel: NonCopyable {
public:
    YacasKernel(const std::string& scripts_path, const Json::Value&);

    void run();
    
private:
    std::string _signature(const zmqpp::message&);
    
    void _send(zmqpp::socket&,
        const std::string& msg_type, const std::string& content, 
        const std::string& parent_header, const std::string& metadata, 
        const std::string& identities);
    
    void _handle_shell(zmqpp::message&&);
    void _handle_engine(const zmqpp::message&);
    
    boost::uuids::random_generator _uuid_gen;

    boost::uuids::uuid _uuid;
    
    zmqpp::context _ctx;
    
    zmqpp::socket _hb_socket;
    zmqpp::socket _iopub_socket;
    zmqpp::socket _control_socket;
    zmqpp::socket _stdin_socket;
    zmqpp::socket _shell_socket;
    
    zmqpp::socket _engine_socket;
    
    HMAC_SHA256 _auth;
    
    unsigned long _execution_count;
    
    YacasEngine _engine;
    
    bool _tex_output;
    std::stringstream _side_effects;
    CYacas _yacas;

    std::map<unsigned long, zmqpp::message> _execute_requests;
    
    bool _shutdown;
};

#endif
