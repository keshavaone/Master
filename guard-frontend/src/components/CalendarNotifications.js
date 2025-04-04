import React, { useState, useEffect } from 'react';
import { CalendarDays, SendHorizontal, Plus, Trash2, RefreshCw, MessageCircle } from 'lucide-react';
import { calendarAPI } from '../services/api';

const CalendarNotifications = ({ darkMode }) => {
  const [subscriptions, setSubscriptions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [sendStatus, setSendStatus] = useState(null);
  const [newSubscription, setNewSubscription] = useState({ name: '', url: '' });
  const [sendOptions, setSendOptions] = useState({
    daysAhead: 0,
    method: 'whatsapp',
    recipient: ''
  });
  
  // Color scheme based on dark/light mode
  const colors = darkMode ? {
    bg: '#121826',
    card: '#1E293B',
    text: '#E2E8F0',
    textDim: '#94A3B8',
    accent: '#3B82F6',
    accentHover: '#2563EB',
    border: '#334155',
    success: '#10B981',
    error: '#EF4444'
  } : {
    bg: '#F8FAFC',
    card: '#FFFFFF',
    text: '#334155',
    textDim: '#64748B',
    accent: '#3B82F6',
    accentHover: '#2563EB',
    border: '#E2E8F0',
    success: '#10B981',
    error: '#EF4444'
  };

  useEffect(() => {
    fetchSubscriptions();
  }, []);

  const fetchSubscriptions = async () => {
    setLoading(true);
    try {
      const response = await calendarAPI.listSubscriptions();
      setSubscriptions(response.data || []);
    } catch (error) {
      console.error('Error fetching calendar subscriptions:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSendCalendarSummary = async () => {
    setLoading(true);
    setSendStatus({ type: 'info', message: 'Sending calendar summary...' });
    
    try {
      const response = await calendarAPI.sendCalendarSummary(
        sendOptions.daysAhead, 
        sendOptions.method, 
        sendOptions.recipient || null
      );
      
      if (response.data && response.data.whatsapp) {
        setSendStatus({ type: 'success', message: 'Calendar summary sent successfully!' });
      } else {
        setSendStatus({ type: 'error', message: 'Failed to send calendar summary.' });
      }
    } catch (error) {
      console.error('Error sending calendar summary:', error);
      setSendStatus({ type: 'error', message: `Error: ${error.response?.data?.message || error.message}` });
    } finally {
      setLoading(false);
      // Clear status after 5 seconds
      setTimeout(() => setSendStatus(null), 5000);
    }
  };

  const handleAddSubscription = async (e) => {
    e.preventDefault();
    if (!newSubscription.name || !newSubscription.url) return;

    setLoading(true);
    try {
      await calendarAPI.addSubscription(newSubscription.name, newSubscription.url);
      setNewSubscription({ name: '', url: '' });
      fetchSubscriptions();
    } catch (error) {
      console.error('Error adding subscription:', error);
      setSendStatus({ type: 'error', message: `Error adding subscription: ${error.response?.data?.message || error.message}` });
      setTimeout(() => setSendStatus(null), 5000);
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveSubscription = async (urlOrName) => {
    setLoading(true);
    try {
      await calendarAPI.removeSubscription(urlOrName);
      fetchSubscriptions();
    } catch (error) {
      console.error('Error removing subscription:', error);
      setSendStatus({ type: 'error', message: `Error removing subscription: ${error.response?.data?.message || error.message}` });
      setTimeout(() => setSendStatus(null), 5000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <CalendarDays className="h-6 w-6 mr-2" style={{ color: colors.accent }} />
          <h2 className="text-xl font-bold">Calendar Notifications</h2>
        </div>
        <button 
          className="flex items-center bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded text-white text-sm"
          onClick={fetchSubscriptions}
          disabled={loading}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </button>
      </div>

      {/* Status message */}
      {sendStatus && (
        <div 
          className="p-3 rounded-lg"
          style={{ 
            backgroundColor: sendStatus.type === 'success' 
              ? 'rgba(16, 185, 129, 0.2)' 
              : sendStatus.type === 'error' 
                ? 'rgba(239, 68, 68, 0.2)' 
                : 'rgba(59, 130, 246, 0.2)',
            color: sendStatus.type === 'success' 
              ? colors.success 
              : sendStatus.type === 'error' 
                ? colors.error 
                : colors.accent
          }}
        >
          {sendStatus.message}
        </div>
      )}

      {/* Send Calendar Summary Card */}
      <div 
        className="rounded-xl p-5"
        style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}
      >
        <h3 className="text-lg font-semibold mb-4">Send Calendar Summary</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm mb-1 opacity-70">Days Ahead</label>
            <select
              className="w-full p-2 rounded-md"
              style={{ backgroundColor: darkMode ? 'rgba(30, 41, 59, 0.8)' : '#F1F5F9', border: `1px solid ${colors.border}` }}
              value={sendOptions.daysAhead}
              onChange={(e) => setSendOptions({...sendOptions, daysAhead: parseInt(e.target.value)})}
            >
              <option value="0">Today</option>
              <option value="1">Tomorrow</option>
              <option value="2">2 days ahead</option>
              <option value="3">3 days ahead</option>
              <option value="7">1 week ahead</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm mb-1 opacity-70">Method</label>
            <select
              className="w-full p-2 rounded-md"
              style={{ backgroundColor: darkMode ? 'rgba(30, 41, 59, 0.8)' : '#F1F5F9', border: `1px solid ${colors.border}` }}
              value={sendOptions.method}
              onChange={(e) => setSendOptions({...sendOptions, method: e.target.value})}
            >
              <option value="whatsapp">WhatsApp</option>
              <option value="sms">SMS</option>
              <option value="both">Both</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm mb-1 opacity-70">Recipient (Optional)</label>
            <input
              type="text"
              placeholder="+1234567890"
              className="w-full p-2 rounded-md"
              style={{ backgroundColor: darkMode ? 'rgba(30, 41, 59, 0.8)' : '#F1F5F9', border: `1px solid ${colors.border}` }}
              value={sendOptions.recipient}
              onChange={(e) => setSendOptions({...sendOptions, recipient: e.target.value})}
            />
          </div>
        </div>
        
        <button
          className="flex items-center bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-md text-white"
          onClick={handleSendCalendarSummary}
          disabled={loading}
        >
          <SendHorizontal className="h-4 w-4 mr-2" />
          Send Calendar Summary
        </button>
      </div>

      {/* Calendar Subscriptions Card */}
      <div 
        className="rounded-xl p-5"
        style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}
      >
        <h3 className="text-lg font-semibold mb-4">Calendar Subscriptions</h3>
        
        {/* Add new subscription form */}
        <form onSubmit={handleAddSubscription} className="mb-6 p-4 rounded-lg bg-blue-500 bg-opacity-10">
          <h4 className="font-medium mb-3">Add Calendar Subscription</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
            <div>
              <label className="block text-sm mb-1 opacity-70">Calendar Name</label>
              <input
                type="text"
                placeholder="Work Calendar"
                className="w-full p-2 rounded-md"
                style={{ backgroundColor: darkMode ? 'rgba(30, 41, 59, 0.8)' : '#F1F5F9', border: `1px solid ${colors.border}` }}
                value={newSubscription.name}
                onChange={(e) => setNewSubscription({...newSubscription, name: e.target.value})}
                required
              />
            </div>
            <div>
              <label className="block text-sm mb-1 opacity-70">iCal URL</label>
              <input
                type="url"
                placeholder="https://example.com/calendar.ics"
                className="w-full p-2 rounded-md"
                style={{ backgroundColor: darkMode ? 'rgba(30, 41, 59, 0.8)' : '#F1F5F9', border: `1px solid ${colors.border}` }}
                value={newSubscription.url}
                onChange={(e) => setNewSubscription({...newSubscription, url: e.target.value})}
                required
              />
            </div>
          </div>
          <button
            type="submit"
            className="flex items-center bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded text-white text-sm"
            disabled={loading || !newSubscription.name || !newSubscription.url}
          >
            <Plus className="h-4 w-4 mr-1" />
            Add Subscription
          </button>
        </form>
        
        {/* Subscription list */}
        <div className="space-y-3">
          <h4 className="font-medium">Your Subscriptions</h4>
          
          {subscriptions.length === 0 ? (
            <div className="text-sm opacity-70 p-3 text-center">
              No calendar subscriptions found.
            </div>
          ) : (
            <div className="space-y-2">
              {subscriptions.map((sub, index) => (
                <div 
                  key={index} 
                  className="flex items-center justify-between p-3 rounded-lg bg-opacity-10"
                  style={{ backgroundColor: darkMode ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)' }}
                >
                  <div>
                    <h5 className="font-medium">{sub.name}</h5>
                    <p className="text-xs opacity-70 truncate" style={{ maxWidth: '250px' }}>{sub.url}</p>
                  </div>
                  <button
                    className="p-1.5 rounded-full hover:bg-red-500 hover:bg-opacity-20 text-red-500"
                    onClick={() => handleRemoveSubscription(sub.url)}
                    disabled={loading}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      
      {/* Usage Information */}
      <div 
        className="rounded-xl p-5"
        style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}
      >
        <div className="flex items-center mb-3">
          <MessageCircle className="h-5 w-5 mr-2" style={{ color: colors.accent }} />
          <h3 className="font-semibold">How It Works</h3>
        </div>
        
        <div className="space-y-2 text-sm opacity-80">
          <p>• Sends calendar events from your iCloud calendar to WhatsApp or SMS</p>
          <p>• Add external calendars via iCal subscription URLs</p>
          <p>• Choose to send today's events or upcoming events</p>
          <p>• Uses Twilio for reliable message delivery</p>
        </div>
      </div>
    </div>
  );
};

export default CalendarNotifications;